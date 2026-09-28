//! The system ARP table: MAC addresses, and evidence that a host exists.
//!
//! A completed ARP entry means the machine answered an ARP request at layer 2,
//! which plenty of hosts do while ignoring ICMP (Windows firewall, printers).
//! Since we ping and connect first, every reachable host on the local subnet
//! gets resolved as a side effect.
//!
//! The whole table is read at once and cached briefly: a scan of a /24 would
//! otherwise spawn an `arp` process per host.

use regex::Regex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// How stale a cached table may be before it's read again. Short, because
/// entries appear as the scan progresses.
const MAX_AGE: Duration = Duration::from_millis(1500);

#[derive(Default)]
struct Cache {
    entries: HashMap<Ipv4Addr, String>,
    read_at: Option<Instant>,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

// The layouts differ per tool, so take the first address of each kind on the
// line rather than trying to match a fixed shape:
//   macOS: ? (192.168.0.1) at b8:27:eb:12:34:56 on en0 ifscope [ethernet]
//   Linux: 192.168.0.10 dev eth0 lladdr 00:11:32:aa:bb:cc REACHABLE
fn ip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b").unwrap())
}

fn mac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}\b").unwrap())
}

/// macOS drops leading zeros (0:1a:2b:...), so pad each octet.
pub fn normalise(raw: &str) -> String {
    raw.split([':', '-'])
        .map(|part| format!("{:0>2}", part.to_uppercase()))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn parse(output: &str) -> HashMap<Ipv4Addr, String> {
    output
        .lines()
        // "(incomplete)" entries are unanswered requests: no evidence of anything.
        .filter(|line| !line.contains("incomplete") && !line.contains("ff:ff:ff:ff:ff:ff"))
        .filter_map(|line| {
            let ip = ip_re().find(line)?.as_str().parse().ok()?;
            Some((ip, normalise(mac_re().find(line)?.as_str())))
        })
        .collect()
}

/// The MAC for `ip`, reading the table again if the cache has gone stale.
pub async fn lookup(ip: Ipv4Addr) -> Option<String> {
    let mut cache = cache().lock().await;
    if cache.read_at.is_none_or(|at| at.elapsed() > MAX_AGE) {
        let flag = if cfg!(target_os = "windows") {
            "-a"
        } else {
            "-an"
        };
        cache.entries = parse(&crate::scanner::run("arp", &[flag]).await);
        cache.read_at = Some(Instant::now());
    }
    cache.entries.get(&ip).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_and_linux_tables() {
        let macos = "? (192.168.0.1) at b8:27:eb:12:34:56 on en0 ifscope [ethernet]\n\
                     ? (192.168.0.23) at b8:27:eb:1:2:3 on en0 ifscope [ethernet]\n\
                     ? (192.168.0.99) at (incomplete) on en0 ifscope [ethernet]\n\
                     ? (224.0.0.251) at ff:ff:ff:ff:ff:ff on en0 ifscope permanent [ethernet]";
        let table = parse(macos);
        assert_eq!(table[&"192.168.0.1".parse().unwrap()], "B8:27:EB:12:34:56");
        assert_eq!(table[&"192.168.0.23".parse().unwrap()], "B8:27:EB:01:02:03");
        assert_eq!(
            table.len(),
            2,
            "incomplete and broadcast entries are not evidence"
        );

        let linux = "192.168.0.10 dev eth0 lladdr 00:11:32:aa:bb:cc REACHABLE";
        assert_eq!(
            parse(linux)[&"192.168.0.10".parse().unwrap()],
            "00:11:32:AA:BB:CC"
        );
    }
}
