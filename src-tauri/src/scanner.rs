//! Host probing: ping, TCP port checks, reverse DNS and ARP lookups.

use crate::arp;
use crate::fdlimit;
use crate::icmp;
use crate::probe::{self, Service};
use crate::risk::{self, Finding};
use crate::vendor;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;

/// Max simultaneous port probes against a single host.
const PORT_BATCH: usize = 32;
/// Refuse ranges bigger than a /16. We're annoyed, not unhinged.
const MAX_HOSTS: u32 = 65_536;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HostResult {
    pub ip: String,
    pub alive: bool,
    pub ping_ms: Option<f64>,
    pub hostname: String,
    pub mac: String,
    /// What proved the host exists: "icmp", "port" or "arp".
    #[serde(default)]
    pub alive_via: String,
    #[serde(default)]
    pub vendor: String,
    /// Service labels a device announced over mDNS/SSDP ("AirPlay", "Printer").
    #[serde(default)]
    pub discovered: Vec<String>,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub services: Vec<Service>,
    /// What's worth knowing about what's exposed here.
    #[serde(default)]
    pub risks: Vec<Finding>,
}

#[derive(Serialize)]
pub struct Range {
    pub start: String,
    pub end: String,
    pub cidr: String,
}

/// Everything the user can tune about a scan.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    pub timeout_ms: u64,
    /// Echo requests per host before giving up. Dozing Wi-Fi devices routinely
    /// miss the first one.
    pub attempts: u8,
    pub banners: bool,
    /// Treat a completed ARP entry as proof a host exists.
    pub trust_arp: bool,
    /// Ask the network to introduce itself over mDNS and SSDP first.
    pub discover: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout_ms: 800,
            attempts: 2,
            discover: true,
            banners: true,
            trust_arp: true,
        }
    }
}

impl Options {
    pub fn sanitised(self) -> Self {
        Self {
            timeout_ms: self.timeout_ms.clamp(50, 30_000),
            attempts: self.attempts.clamp(1, 10),
            ..self
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// Cancellation token: a scan is live while the shared generation still
/// matches the one it started with. Bumping the generation stops it.
#[derive(Clone)]
pub struct Cancel {
    pub current: Arc<AtomicU64>,
    pub generation: u64,
}

impl Cancel {
    pub fn is_cancelled(&self) -> bool {
        self.current.load(Ordering::SeqCst) != self.generation
    }
}

// --------------------------------------------------------------------------
// Input parsing
// --------------------------------------------------------------------------

pub fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for chunk in text.split(',').map(str::trim).filter(|c| !c.is_empty()) {
        let parse = |s: &str| -> Result<u16, String> {
            match s.trim().parse::<u32>() {
                Ok(p) if (1..=65535).contains(&p) => Ok(p as u16),
                _ => Err(format!("'{}' is not a real port. Come on.", s.trim())),
            }
        };
        match chunk.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (parse(a)?, parse(b)?);
                ports.extend(a.min(b)..=a.max(b));
            }
            None => ports.push(parse(chunk)?),
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_ip(s: &str) -> Result<Ipv4Addr, String> {
    s.trim()
        .parse()
        .map_err(|_| format!("'{}' is not an IPv4 address. I checked.", s.trim()))
}

/// Everything one scan will visit, from a written specification.
#[derive(Debug)]
pub struct Targets {
    pub ips: Vec<Ipv4Addr>,
    /// As typed, so two scans of the same thing can be compared later.
    pub spec: String,
    pub start: String,
    pub end: String,
}

/// Parse "192.168.0.0/24, 10.0.0.1-50, 10.0.1.7" into addresses to scan.
/// Separators are commas or whitespace; overlapping pieces collapse.
pub fn parse_targets(text: &str) -> Result<Targets, String> {
    let mut ips: Vec<Ipv4Addr> = Vec::new();
    for piece in text
        .split([',', ';', ' ', '\t', '\n'])
        .filter(|p| !p.trim().is_empty())
    {
        let piece = piece.trim();
        let range = if piece.contains('/') {
            let range = cidr_range(piece)?;
            ip_range(&range.start, &range.end)?
        } else if let Some((from, to)) = piece.split_once('-') {
            ip_range(from, &expand_short_end(from, to)?)?
        } else {
            vec![parse_ip(piece)?]
        };
        ips.extend(range);
        if ips.len() > MAX_HOSTS as usize {
            return Err("More than 65,536 addresses? Absolutely not.".into());
        }
    }
    ips.sort_unstable();
    ips.dedup();
    if ips.is_empty() {
        return Err("Give me something to scan. An address, a range, a CIDR block.".into());
    }
    Ok(Targets {
        start: ips.first().expect("not empty").to_string(),
        end: ips.last().expect("not empty").to_string(),
        spec: text.split_whitespace().collect::<Vec<_>>().join(" "),
        ips,
    })
}

/// "192.168.0.1-50" means up to 192.168.0.50, which is how everyone writes it.
fn expand_short_end(from: &str, to: &str) -> Result<String, String> {
    let to = to.trim();
    if to.contains('.') {
        return Ok(to.to_string());
    }
    let last: u8 = to.parse().map_err(|_| {
        format!("'{to}' isn't the end of a range. I expected a number or an address.")
    })?;
    let start = parse_ip(from)?.octets();
    Ok(Ipv4Addr::new(start[0], start[1], start[2], last).to_string())
}

pub fn ip_range(start: &str, end: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (a, b) = (u32::from(parse_ip(start)?), u32::from(parse_ip(end)?));
    let (a, b) = (a.min(b), a.max(b));
    if b - a >= MAX_HOSTS {
        return Err("More than 65,536 addresses? Absolutely not.".into());
    }
    Ok((a..=b).map(Ipv4Addr::from).collect())
}

pub fn cidr_range(cidr: &str) -> Result<Range, String> {
    let bad = || {
        format!(
            "'{}' isn't a CIDR. Try something like 192.168.1.0/24.",
            cidr.trim()
        )
    };
    let (ip, prefix) = cidr.trim().split_once('/').ok_or_else(bad)?;
    let ip = u32::from(ip.trim().parse::<Ipv4Addr>().map_err(|_| bad())?);
    let prefix: u32 = prefix.trim().parse().map_err(|_| bad())?;
    if prefix > 32 {
        return Err(bad());
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let net = ip & mask;
    let bcast = net | !mask;
    // Skip network/broadcast addresses unless the block is too small to have any.
    let (start, end) = if prefix >= 31 {
        (net, bcast)
    } else {
        (net + 1, bcast - 1)
    };
    Ok(Range {
        start: Ipv4Addr::from(start).to_string(),
        end: Ipv4Addr::from(end).to_string(),
        cidr: format!("{}/{}", Ipv4Addr::from(net), prefix),
    })
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// This machine's address on the LAN.
pub fn local_ip() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("10.255.255.255:1").ok()?; // picks a route, sends nothing
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

pub fn local_range() -> Range {
    let ip = local_ip().map_or_else(|| "192.168.1.1".to_string(), |ip| ip.to_string());
    cidr_range(&format!("{ip}/24")).expect("valid /24")
}

// --------------------------------------------------------------------------
// Probing
// --------------------------------------------------------------------------

fn ping_time_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"time[=<]\s*([\d.]+)\s*ms").unwrap())
}

fn mac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}").unwrap())
}

/// Ping until one attempt answers. Prefers an unprivileged ICMP socket,
/// which needs no process and one descriptor for the whole scan.
async fn ping(ip: Ipv4Addr, opts: &Options, cancel: &Cancel) -> Option<f64> {
    for attempt in 0..opts.attempts {
        if attempt > 0 && cancel.is_cancelled() {
            break;
        }
        let rtt = match icmp::shared() {
            Some(pinger) => pinger.ping(ip, opts.timeout()).await,
            None => ping_command(ip, opts.timeout_ms).await,
        };
        if rtt.is_some() {
            return rtt;
        }
    }
    None
}

async fn ping_command(ip: Ipv4Addr, timeout_ms: u64) -> Option<f64> {
    let ip_s = ip.to_string();
    let mut cmd = Command::new("ping");
    if cfg!(target_os = "windows") {
        cmd.args(["-n", "1", "-w", &timeout_ms.to_string(), &ip_s]);
    } else if cfg!(target_os = "macos") {
        cmd.args(["-c", "1", "-W", &timeout_ms.to_string(), &ip_s]);
    } else {
        cmd.args([
            "-c",
            "1",
            "-W",
            &(timeout_ms / 1000).max(1).to_string(),
            &ip_s,
        ]);
    }
    cmd.kill_on_drop(true);
    let _fds = fdlimit::acquire(fdlimit::PROCESS).await;
    let started = Instant::now();
    let out = timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Some(
        ping_time_re()
            .captures(&stdout)
            .and_then(|c| c[1].parse().ok())
            .unwrap_or_else(|| started.elapsed().as_secs_f64() * 1000.0),
    )
}

async fn tcp_open(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let _fds = fdlimit::acquire(fdlimit::SOCKET).await;
    matches!(
        timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

async fn open_ports(ip: Ipv4Addr, ports: &[u16], timeout_ms: u64, cancel: &Cancel) -> Vec<u16> {
    let mut open = Vec::new();
    for batch in ports.chunks(PORT_BATCH) {
        if cancel.is_cancelled() {
            break;
        }
        let checks = batch
            .iter()
            .map(|&p| async move { (p, tcp_open(ip, p, timeout_ms).await) });
        open.extend(
            futures::future::join_all(checks)
                .await
                .into_iter()
                .filter_map(|(p, ok)| ok.then_some(p)),
        );
    }
    open
}

async fn reverse_dns(ip: Ipv4Addr) -> String {
    let _fds = fdlimit::acquire(fdlimit::SOCKET).await;
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)));
    match timeout(Duration::from_secs(3), lookup).await {
        Ok(Ok(Ok(name))) if name != ip.to_string() => name,
        _ => String::new(),
    }
}

pub(crate) async fn run(program: &str, args: &[&str]) -> String {
    let _fds = fdlimit::acquire(fdlimit::PROCESS).await;
    let out = timeout(
        Duration::from_secs(2),
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await;
    match out {
        Ok(Ok(out)) => String::from_utf8_lossy(&out.stdout).into_owned(),
        _ => String::new(),
    }
}

fn normalise_mac(raw: &str) -> String {
    // macOS drops leading zeros (0:1a:2b:...), so pad each octet.
    raw.split([':', '-'])
        .map(|p| format!("{:0>2}", p.to_uppercase()))
        .collect::<Vec<_>>()
        .join(":")
}

/// Find the MAC of the interface that owns `ip` in `ifconfig` output. Each
/// interface block starts on an unindented line.
fn mac_from_ifconfig(output: &str, ip: &str) -> Option<String> {
    let needle = format!("inet {ip} ");
    let mut blocks: Vec<String> = Vec::new();
    for line in output.lines() {
        match blocks.last_mut() {
            Some(block) if line.starts_with(char::is_whitespace) => {
                block.push_str(line);
                block.push('\n');
            }
            _ => blocks.push(format!("{line}\n")),
        }
    }
    let block = blocks.iter().find(|b| b.contains(&needle))?;
    let ether = block
        .lines()
        .find(|l| l.trim_start().starts_with("ether "))?;
    mac_re().find(ether).map(|m| normalise_mac(m.as_str()))
}

async fn mac_address(ip: Ipv4Addr) -> String {
    let ip_s = ip.to_string();
    if let Some(mac) = arp::lookup(ip).await {
        return mac;
    }
    // Our own address never shows up in the ARP cache; read it off the interface.
    if !cfg!(target_os = "windows") {
        if let Some(mac) = mac_from_ifconfig(&run("ifconfig", &[]).await, &ip_s) {
            return mac;
        }
    }
    String::new()
}

async fn identify_services(
    ip: Ipv4Addr,
    ports: &[u16],
    timeout_ms: u64,
    cancel: &Cancel,
) -> Vec<Service> {
    if cancel.is_cancelled() {
        return Vec::new();
    }
    let connect = Duration::from_millis(timeout_ms);
    futures::future::join_all(ports.iter().map(|&p| probe::identify(ip, p, connect)))
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Fill in MAC, vendor and hostname for a host we didn't probe into being
/// alive (one that only answered mDNS or SSDP).
pub async fn fill_identity(host: &mut HostResult) {
    let Ok(ip) = host.ip.parse::<Ipv4Addr>() else {
        return;
    };
    if host.mac.is_empty() {
        host.mac = mac_address(ip).await;
    }
    if host.vendor.is_empty() {
        host.vendor = vendor::lookup(&host.mac);
    }
    if host.hostname.is_empty() {
        host.hostname = reverse_dns(ip).await;
    }
}

/// Is this up right now? A port means that service specifically; without
/// one, any sign of the host will do.
pub async fn check_alive(ip: Ipv4Addr, port: Option<u16>, opts: &Options) -> bool {
    let cancel = Cancel {
        current: Arc::new(AtomicU64::new(0)),
        generation: 0,
    };
    match port {
        Some(port) => tcp_open(ip, port, opts.timeout_ms).await,
        None => {
            ping(ip, opts, &cancel).await.is_some()
                || (opts.trust_arp && arp::lookup(ip).await.is_some())
        }
    }
}

pub async fn scan_host(ip: Ipv4Addr, ports: &[u16], opts: &Options, cancel: &Cancel) -> HostResult {
    // Hosts that drop ICMP may still have open ports, so probe both at once.
    let (ping_ms, ports) = tokio::join!(
        ping(ip, opts, cancel),
        open_ports(ip, ports, opts.timeout_ms, cancel)
    );
    let mut alive_via = match (ping_ms.is_some(), ports.is_empty()) {
        (true, _) => "icmp",
        (false, false) => "port",
        (false, true) => "",
    };
    // Silent host: our pings and connects will have resolved ARP for it if it
    // is really there, so a completed entry is evidence.
    let mut mac = String::new();
    if alive_via.is_empty() && opts.trust_arp && !cancel.is_cancelled() {
        if let Some(found) = arp::lookup(ip).await {
            mac = found;
            alive_via = "arp";
        }
    }

    let alive = !alive_via.is_empty();
    let mut host = HostResult {
        ip: ip.to_string(),
        alive,
        ping_ms,
        alive_via: alive_via.to_string(),
        mac,
        ports,
        ..Default::default()
    };
    if !alive || cancel.is_cancelled() {
        return host;
    }

    let (hostname, mac, services) = tokio::join!(reverse_dns(ip), mac_address(ip), async {
        if opts.banners {
            identify_services(ip, &host.ports, opts.timeout_ms, cancel).await
        } else {
            Vec::new()
        }
    });
    host.hostname = hostname;
    if !mac.is_empty() {
        host.mac = mac;
    }
    host.vendor = vendor::lookup(&host.mac);
    host.services = services;
    host.risks = risk::assess(&host, unix_seconds());
    host
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports() {
        assert_eq!(parse_ports("80, 22,80-82").unwrap(), vec![22, 80, 81, 82]);
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn own_mac_from_ifconfig() {
        let out = "lo0: flags=8049<UP,LOOPBACK> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\
                   en0: flags=8863<UP,BROADCAST> mtu 1500\n\tether 3c:6:30:a:b:cd\n\
                   \tinet 192.168.0.54 netmask 0xffffff00 broadcast 192.168.0.255\n";
        assert_eq!(
            mac_from_ifconfig(out, "192.168.0.54").as_deref(),
            Some("3C:06:30:0A:0B:CD")
        );
        assert_eq!(mac_from_ifconfig(out, "127.0.0.1"), None);
    }

    #[test]
    fn targets_accept_every_shape() {
        let t = parse_targets("192.168.0.0/30, 10.0.0.1-3 10.0.1.7").unwrap();
        assert_eq!(
            t.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.3",
                "10.0.1.7",
                "192.168.0.1",
                "192.168.0.2"
            ]
        );
        assert_eq!(
            (t.start.as_str(), t.end.as_str()),
            ("10.0.0.1", "192.168.0.2")
        );
        assert_eq!(t.spec, "192.168.0.0/30, 10.0.0.1-3 10.0.1.7");

        // Overlapping pieces are scanned once.
        let overlap = parse_targets("10.0.0.1-5, 10.0.0.3-7").unwrap();
        assert_eq!(overlap.ips.len(), 7);

        // A full address on the right of the dash still works.
        assert_eq!(parse_targets("10.0.0.1-10.0.0.4").unwrap().ips.len(), 4);
    }

    #[test]
    fn targets_complain_usefully() {
        assert!(parse_targets("").is_err());
        assert!(parse_targets("   ").is_err());
        assert!(parse_targets("not-an-ip").is_err());
        assert!(parse_targets("10.0.0.1-nonsense").is_err());
        assert!(parse_targets("10.0.0.0/8").is_err(), "too many addresses");
    }

    #[test]
    fn ranges() {
        assert_eq!(ip_range("10.0.0.5", "10.0.0.1").unwrap().len(), 5);
        assert!(ip_range("10.0.0.0", "10.2.0.0").is_err());
        let r = cidr_range("192.168.4.77/24").unwrap();
        assert_eq!(
            (r.start.as_str(), r.end.as_str(), r.cidr.as_str()),
            ("192.168.4.1", "192.168.4.254", "192.168.4.0/24")
        );
        assert_eq!(cidr_range("10.0.0.1/32").unwrap().start, "10.0.0.1");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn localhost_is_alive() {
        let cancel = Cancel {
            current: Arc::new(AtomicU64::new(1)),
            generation: 1,
        };
        let opts = Options {
            timeout_ms: 500,
            attempts: 1,
            ..Options::default()
        };
        let r = scan_host(Ipv4Addr::LOCALHOST, &[1], &opts, &cancel).await;
        assert!(r.alive);
        assert!(r.ping_ms.is_some());
        assert_eq!(r.alive_via, "icmp");
    }
}
