//! Turning what a service told us into something worth acting on.
//!
//! Everything here is inference from an outside view: an open port and what
//! answered on it. We never authenticate, so findings say what is *exposed*,
//! not that it's insecure. On a home LAN plenty of this is fine and expected -
//! hence severities rather than alarms, and wording that says where the risk
//! would be.

use crate::scanner::HostResult;
use serde::{Deserialize, Serialize};

/// Certificates expiring sooner than this are worth mentioning.
const EXPIRY_SOON: i64 = 30 * 24 * 3600;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Finding {
    /// "high", "medium" or "low".
    pub severity: String,
    pub title: String,
    /// One sentence on why it matters.
    pub detail: String,
    pub port: u16,
}

impl Finding {
    fn new(severity: &str, port: u16, title: &str, detail: &str) -> Self {
        Self {
            severity: severity.into(),
            title: title.into(),
            detail: detail.into(),
            port,
        }
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

/// `now` is unix seconds, so certificate expiry can be judged.
pub fn assess(host: &HostResult, now: i64) -> Vec<Finding> {
    let mut findings = Vec::new();

    for &port in &host.ports {
        findings.extend(exposure(port));
    }

    for service in &host.services {
        let port = service.port;
        if let Some(expires) = service.cert_expires {
            if expires < now {
                findings.push(Finding::new(
                    "high",
                    port,
                    "Certificate has expired",
                    "Clients will warn or refuse to connect until it's renewed.",
                ));
            } else if expires - now < EXPIRY_SOON {
                let days = (expires - now) / (24 * 3600);
                findings.push(Finding::new(
                    "medium",
                    port,
                    &format!("Certificate expires in {days} days"),
                    "Renew it before things start refusing to connect.",
                ));
            }
        }
        match service.tls_version.as_str() {
            "TLS 1.0" | "TLS 1.1" => findings.push(Finding::new(
                "medium",
                port,
                &format!("Obsolete {}", service.tls_version),
                "Withdrawn in 2021 and unsupported by current browsers.",
            )),
            _ => {}
        }
        // Plain HTTP that asks for credentials sends them in the clear.
        if service.name == "http" && looks_like_a_login(&service.summary) {
            findings.push(Finding::new(
                "medium",
                port,
                "Login page served over plain HTTP",
                "Anything typed into it crosses the network unencrypted.",
            ));
        }
    }

    findings.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(a.port.cmp(&b.port))
    });
    findings.dedup_by(|a, b| a.title == b.title && a.port == b.port);
    findings
}

/// Services whose exposure is worth knowing about, by port.
fn exposure(port: u16) -> Option<Finding> {
    let (severity, title, detail) = match port {
        23 => (
            "high",
            "Telnet is open",
            "Telnet has no encryption: passwords cross the network in plain text.",
        ),
        21 => (
            "medium",
            "FTP is open",
            "Plain FTP sends credentials and files unencrypted.",
        ),
        5900 => (
            "medium",
            "VNC is open",
            "Screen sharing, often with a weak password or none at all.",
        ),
        3389 => (
            "medium",
            "Remote Desktop is open",
            "A favourite target for password guessing if it ever reaches the internet.",
        ),
        445 | 139 => (
            "low",
            "Windows file sharing is open",
            "Normal on a home network; a problem if this host faces the internet.",
        ),
        6379 => (
            "high",
            "Redis is reachable",
            "Redis listens without a password by default, which grants full access to its data.",
        ),
        27017 => (
            "high",
            "MongoDB is reachable",
            "Older defaults allow unauthenticated access to every database.",
        ),
        9200 => (
            "high",
            "Elasticsearch is reachable",
            "The HTTP API is often unauthenticated, exposing all indexed data.",
        ),
        11211 => (
            "high",
            "Memcached is reachable",
            "Unauthenticated by design, and usable to amplify denial-of-service traffic.",
        ),
        3306 | 5432 | 1433 => (
            "medium",
            "Database port is open",
            "Databases are usually best reachable only from the machines that need them.",
        ),
        2375 => (
            "high",
            "Docker API is open",
            "An unauthenticated Docker socket is equivalent to root on the host.",
        ),
        161 => (
            "low",
            "SNMP is open",
            "Default community strings often reveal device configuration.",
        ),
        _ => return None,
    };
    Some(Finding::new(severity, port, title, detail))
}

/// A page title that suggests somewhere to type a password.
fn looks_like_a_login(summary: &str) -> bool {
    const HINTS: &[&str] = &["login", "sign in", "log in", "admin", "router", "password"];
    let lower = summary.to_lowercase();
    HINTS.iter().any(|hint| lower.contains(hint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::Service;

    const NOW: i64 = 1_800_000_000;

    fn host(ports: &[u16], services: Vec<Service>) -> HostResult {
        HostResult {
            ip: "10.0.0.5".into(),
            alive: true,
            ports: ports.to_vec(),
            services,
            ..Default::default()
        }
    }

    fn https(port: u16, expires: Option<i64>, version: &str) -> Service {
        Service {
            port,
            name: "https".into(),
            cert_expires: expires,
            tls_version: version.into(),
            ..Default::default()
        }
    }

    #[test]
    fn flags_exposed_services_by_severity() {
        let findings = assess(&host(&[23, 445, 6379, 22], vec![]), NOW);
        let titles: Vec<_> = findings
            .iter()
            .map(|f| (f.severity.as_str(), f.port))
            .collect();
        assert_eq!(titles, [("high", 23), ("high", 6379), ("low", 445)]);
        assert!(
            !findings.iter().any(|f| f.port == 22),
            "ssh is not a finding"
        );
        // Sorted worst-first, so the badge can take the head of the list.
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn judges_certificates_against_now() {
        let expired = assess(
            &host(&[443], vec![https(443, Some(NOW - 86400), "TLS 1.3")]),
            NOW,
        );
        assert_eq!(expired[0].title, "Certificate has expired");

        let soon = assess(
            &host(&[443], vec![https(443, Some(NOW + 5 * 86400), "TLS 1.3")]),
            NOW,
        );
        assert_eq!(soon[0].title, "Certificate expires in 5 days");

        let fine = assess(
            &host(&[443], vec![https(443, Some(NOW + 200 * 86400), "TLS 1.3")]),
            NOW,
        );
        assert!(fine.is_empty(), "a healthy certificate is not a finding");
    }

    #[test]
    fn flags_obsolete_tls_but_not_current_versions() {
        let old = assess(&host(&[8443], vec![https(8443, None, "TLS 1.0")]), NOW);
        assert_eq!(old[0].title, "Obsolete TLS 1.0");
        assert!(assess(&host(&[8443], vec![https(8443, None, "TLS 1.2")]), NOW).is_empty());
    }

    #[test]
    fn spots_logins_served_without_encryption() {
        let login = Service {
            port: 80,
            name: "http".into(),
            summary: "Hub 4 — Login".into(),
            ..Default::default()
        };
        let findings = assess(&host(&[80], vec![login]), NOW);
        assert_eq!(findings[0].title, "Login page served over plain HTTP");

        let ordinary = Service {
            port: 80,
            name: "http".into(),
            summary: "Welcome to nginx".into(),
            ..Default::default()
        };
        assert!(assess(&host(&[80], vec![ordinary]), NOW).is_empty());
    }

    #[test]
    fn an_ordinary_host_raises_nothing() {
        let findings = assess(
            &host(
                &[22, 80, 443],
                vec![https(443, Some(NOW + 90 * 86400), "TLS 1.3")],
            ),
            NOW,
        );
        assert!(findings.is_empty());
    }
}
