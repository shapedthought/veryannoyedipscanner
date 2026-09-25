//! Service identification for open ports: passive banners, HTTP titles and
//! TLS certificate names. Reads only - nothing is sent beyond a plain GET /.

use crate::fdlimit;
use regex::Regex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const BANNER_WAIT: Duration = Duration::from_millis(1500);
const HTTP_WAIT: Duration = Duration::from_secs(3);
const MAX_BODY: usize = 64 * 1024;

/// Ports we speak TLS to before trying anything else.
const TLS_PORTS: &[u16] = &[
    443, 465, 636, 853, 993, 995, 4443, 5001, 7443, 8006, 8443, 9443, 10443,
];
/// Ports where the server waits for us, so try HTTP straight away.
const HTTP_PORTS: &[u16] = &[
    80, 81, 591, 3000, 5000, 7080, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9080,
];
/// Binary protocols where poking with HTTP gets us nothing but a hang.
const NO_PROBE: &[u16] = &[53, 111, 135, 137, 139, 445, 3389, 5985, 5986, 62078];

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Service {
    pub port: u16,
    /// Protocol label, e.g. "http", "ssh", "smb".
    pub name: String,
    /// One-line human summary: page title, software version, etc.
    pub summary: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub cert: Vec<String>,
}

#[rustfmt::skip]
pub fn port_name(port: u16) -> &'static str {
    match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns",
        80 | 81 | 591 | 8000 | 8008 | 8080 | 8081 | 8088 | 8888 => "http",
        110 => "pop3", 111 => "rpcbind", 135 => "msrpc", 137 | 139 => "netbios",
        143 => "imap", 161 => "snmp", 389 => "ldap", 443 | 8443 | 9443 | 10443 => "https",
        445 => "smb", 465 | 587 => "smtp", 548 => "afp", 554 => "rtsp", 631 => "ipp",
        636 => "ldaps", 853 => "dns-tls", 873 => "rsync", 993 => "imaps", 995 => "pop3s",
        1433 => "mssql", 1883 => "mqtt", 2049 => "nfs", 3306 => "mysql", 3389 => "rdp",
        5000 | 5001 => "nas/upnp", 5353 => "mdns", 5432 => "postgres", 5900 => "vnc",
        5985 | 5986 => "winrm", 6379 => "redis", 8006 => "proxmox", 8123 => "home-assistant",
        9100 => "printer", 9200 => "elasticsearch", 27017 => "mongodb", 32400 => "plex",
        62078 => "apple-sync",
        _ => "",
    }
}

pub async fn identify(ip: Ipv4Addr, port: u16, connect_timeout: Duration) -> Option<Service> {
    // Every step below uses one connection at a time, so one descriptor covers it.
    let _fds = fdlimit::acquire(fdlimit::SOCKET).await;
    let named = || {
        let name = port_name(port);
        (!name.is_empty()).then(|| Service {
            port,
            name: name.into(),
            ..Default::default()
        })
    };
    if NO_PROBE.contains(&port) {
        return named();
    }
    if TLS_PORTS.contains(&port) {
        return http(ip, port, true, connect_timeout).await.or_else(named);
    }
    if !HTTP_PORTS.contains(&port) {
        if let Some(svc) = passive_banner(ip, port, connect_timeout).await {
            return Some(svc);
        }
    }
    if let Some(svc) = http(ip, port, false, connect_timeout).await {
        return Some(svc);
    }
    if let Some(svc) = http(ip, port, true, connect_timeout).await {
        return Some(svc);
    }
    named()
}

// --------------------------------------------------------------------------
// Passive banners (SSH, FTP, SMTP, VNC, MySQL...)
// --------------------------------------------------------------------------

async fn passive_banner(ip: Ipv4Addr, port: u16, connect_timeout: Duration) -> Option<Service> {
    let mut tcp = connect(ip, port, connect_timeout).await?;
    let bytes = read_until(&mut tcp, 1024, BANNER_WAIT, |b| b.contains(&b'\n')).await;
    if bytes.is_empty() {
        return None;
    }
    let text = printable(&bytes);
    let first = text.lines().next().unwrap_or("").trim();
    let (name, summary) = if let Some(rest) = first.strip_prefix("SSH-") {
        (
            "ssh",
            rest.split_once('-').map_or(rest, |(_, v)| v).to_string(),
        )
    } else if first.starts_with("RFB ") {
        ("vnc", first.to_string())
    } else if first.starts_with("+OK") {
        ("pop3", first.trim_start_matches("+OK").trim().to_string())
    } else if first.starts_with("* OK") {
        ("imap", first.trim_start_matches("* OK").trim().to_string())
    } else if let Some(rest) = first.strip_prefix("220") {
        let name = if port_name(port).is_empty() {
            "ftp/smtp"
        } else {
            port_name(port)
        };
        (name, rest.trim_start_matches(['-', ' ']).to_string())
    } else {
        (port_name(port), first.to_string())
    };
    Some(Service {
        port,
        name: if name.is_empty() {
            "banner".into()
        } else {
            name.into()
        },
        summary: truncate(&summary, 100),
        ..Default::default()
    })
}

/// Keep runs of printable ASCII so binary greetings (MySQL, Redis) still
/// yield their version string.
fn printable(bytes: &[u8]) -> String {
    let text: String = bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) || b == b'\n' {
                b as char
            } else {
                '\u{0}'
            }
        })
        .collect();
    text.split('\u{0}')
        .filter(|run| run.trim().len() >= 4)
        .collect::<Vec<_>>()
        .join(" ")
}

// --------------------------------------------------------------------------
// HTTP(S)
// --------------------------------------------------------------------------

struct HttpResponse {
    status: u16,
    server: String,
    location: String,
    title: String,
}

async fn http(ip: Ipv4Addr, port: u16, tls: bool, connect_timeout: Duration) -> Option<Service> {
    let mut path = String::from("/");
    let mut tls_now = tls;
    let mut cert = Vec::new();
    let mut note = String::new();
    let mut resp = None;

    // Follow up to two redirects, but only while they stay on this ip:port.
    for _ in 0..3 {
        // A failed hop after a redirect still leaves us the redirect itself.
        let Some((bytes, names)) = fetch(ip, port, tls_now, &path, connect_timeout).await else {
            break;
        };
        let Some(r) = parse_http(&bytes) else { break };
        if cert.is_empty() {
            cert = names;
        }
        let redirect =
            (300..400).contains(&r.status) && r.title.is_empty() && !r.location.is_empty();
        if redirect {
            note = format!("→ {}", r.location);
            if let Some((next_tls, next_path)) = follow(&r.location, ip, port, tls_now) {
                resp = Some((r, tls_now));
                tls_now = next_tls;
                path = next_path;
                continue;
            }
        }
        resp = Some((r, tls_now));
        break;
    }

    let (r, used_tls) = resp?;
    let summary = if !r.title.is_empty() {
        r.title
    } else if !note.is_empty() {
        note
    } else if !r.server.is_empty() {
        r.server.clone()
    } else {
        format!("HTTP {}", r.status)
    };
    Some(Service {
        port,
        name: if used_tls { "https" } else { "http" }.into(),
        summary: truncate(&summary, 120),
        server: truncate(&r.server, 80),
        cert,
    })
}

/// Resolve a Location header. Returns (tls, path) if it points back at the
/// same ip:port, otherwise None (we just report where it goes).
fn follow(location: &str, ip: Ipv4Addr, port: u16, tls: bool) -> Option<(bool, String)> {
    if location.starts_with('/') && !location.starts_with("//") {
        return Some((tls, location.to_string()));
    }
    let (scheme_tls, rest) = match location.split_once("://") {
        Some(("https", rest)) => (true, rest),
        Some(("http", rest)) => (false, rest),
        _ => return None,
    };
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
    let (host, target_port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, if scheme_tls { 443 } else { 80 }),
    };
    (host == ip.to_string() && target_port == port).then_some((scheme_tls, path))
}

async fn fetch(
    ip: Ipv4Addr,
    port: u16,
    tls: bool,
    path: &str,
    connect_timeout: Duration,
) -> Option<(Vec<u8>, Vec<String>)> {
    let tcp = connect(ip, port, connect_timeout).await?;
    let host = match (tls, port) {
        (false, 80) | (true, 443) => ip.to_string(),
        _ => format!("{ip}:{port}"),
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: VeryAnnoyedIPScanner/0.1 (sigh)\r\n\
         Accept: text/html,*/*;q=0.8\r\nConnection: close\r\n\r\n"
    );
    if tls {
        let name = ServerName::IpAddress(IpAddr::V4(ip).into());
        let mut stream = timeout(
            HTTP_WAIT,
            TlsConnector::from(tls_config()).connect(name, tcp),
        )
        .await
        .ok()?
        .ok()?;
        let names = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| cert_names(c))
            .unwrap_or_default();
        Some((exchange(&mut stream, &request).await?, names))
    } else {
        let mut tcp = tcp;
        Some((exchange(&mut tcp, &request).await?, Vec::new()))
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &str,
) -> Option<Vec<u8>> {
    timeout(HTTP_WAIT, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let bytes = read_until(stream, MAX_BODY, HTTP_WAIT, |b| {
        b.windows(8).any(|w| w.eq_ignore_ascii_case(b"</title>"))
    })
    .await;
    (!bytes.is_empty()).then_some(bytes)
}

fn parse_http(bytes: &[u8]) -> Option<HttpResponse> {
    let text = String::from_utf8_lossy(bytes);
    if !text.starts_with("HTTP/") {
        return None;
    }
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let mut server = String::new();
    let mut location = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "server" => server = v.trim().to_string(),
                "location" => location = v.trim().to_string(),
                _ => {}
            }
        }
    }
    Some(HttpResponse {
        status,
        server,
        location,
        title: extract_title(body),
    })
}

fn extract_title(body: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());
    let Some(raw) = re.captures(body).map(|c| c[1].to_string()) else {
        return String::new();
    };
    let decoded = raw
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#039;", "'")
        .replace("&nbsp;", " ");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

// --------------------------------------------------------------------------
// TLS: accept any certificate - we're identifying devices, not trusting them.
// --------------------------------------------------------------------------

#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("ring supports default TLS versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// Subject CN plus DNS SANs, deduplicated, capped at five.
fn cert_names(der: &CertificateDer<'_>) -> Vec<String> {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der.as_ref()) else {
        return Vec::new();
    };
    let mut names: Vec<String> = cert
        .subject()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok().map(str::to_string))
        .collect();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = gn {
                names.push(dns.to_string());
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));
    names.truncate(5);
    names
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

async fn connect(ip: Ipv4Addr, port: u16, connect_timeout: Duration) -> Option<TcpStream> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()
}

/// Read until EOF, `limit` bytes, the deadline, or `done` says we have enough.
async fn read_until<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
    wait: Duration,
    done: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    let deadline = Instant::now() + wait;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while buf.len() < limit {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                buf.extend_from_slice(&chunk[..n]);
                if done(&buf) {
                    break;
                }
            }
            _ => break,
        }
    }
    buf
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Type: text/html\r\n\r\n\
                    <html><head><TITLE>\n  Synology &amp; Friends\n</TITLE>";
        let r = parse_http(raw).unwrap();
        assert_eq!(
            (r.status, r.server.as_str(), r.title.as_str()),
            (200, "nginx/1.25", "Synology & Friends")
        );
        assert!(parse_http(b"SSH-2.0-OpenSSH").is_none());
    }

    #[test]
    fn follows_only_same_origin() {
        let ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            follow("/login", ip, 8080, false),
            Some((false, "/login".into()))
        );
        assert_eq!(
            follow("https://10.0.0.5:8080/x", ip, 8080, false),
            Some((true, "/x".into()))
        );
        assert_eq!(follow("https://10.0.0.5/", ip, 80, false), None);
        assert_eq!(follow("http://nas.local/", ip, 80, false), None);
    }

    #[test]
    fn binary_banner_keeps_version() {
        let mysql = b"J\x00\x00\x00\n8.0.36-0ubuntu\x00\x12\x00\x00\x00abc";
        assert!(printable(mysql).contains("8.0.36-0ubuntu"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn identifies_local_http_server() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(
                    b"HTTP/1.0 200 OK\r\nServer: Grumpy/1.0\r\n\r\n<title>Hello there</title>",
                )
                .await;
        });
        let svc = http(Ipv4Addr::LOCALHOST, port, false, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            (svc.name.as_str(), svc.summary.as_str(), svc.server.as_str()),
            ("http", "Hello there", "Grumpy/1.0")
        );
    }
}
