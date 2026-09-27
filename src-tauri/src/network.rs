//! Which network are we on?
//!
//! Not "what address range", which is the question the app used to ask:
//! half the world is 192.168.0.0/24, so the range says nothing about *whose*
//! network it is. The default gateway's MAC address does, and it survives
//! DHCP, reboots and address changes.

use crate::arp;
use crate::scanner;
use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Fingerprint {
    /// Stable identity for this network: the gateway's MAC where we can see
    /// it, otherwise the subnet, which is better than nothing.
    pub id: String,
    pub gateway_ip: String,
    pub gateway_mac: String,
    /// macOS hides this unless the app has Location Services permission, so
    /// treat it as a bonus rather than something to rely on.
    pub ssid: String,
    pub interface: String,
    /// The local /24, as a starting suggestion for what to scan.
    pub subnet: String,
}

pub async fn detect() -> Fingerprint {
    let route = scanner::run("route", &["-n", "get", "default"]).await;
    let gateway_ip = field(&route, "gateway:");
    let interface = field(&route, "interface:");
    let gateway_mac = match gateway_ip.parse::<Ipv4Addr>() {
        Ok(ip) => arp::lookup(ip).await.unwrap_or_default(),
        Err(_) => String::new(),
    };
    let ssid = ssid(&interface).await;
    let subnet = scanner::local_range().cidr;

    let id = if gateway_mac.is_empty() {
        format!("subnet:{subnet}")
    } else {
        format!("gw:{gateway_mac}")
    };
    Fingerprint {
        id,
        gateway_ip,
        gateway_mac,
        ssid,
        interface,
        subnet,
    }
}

/// A name to suggest for a new profile: the network's own name if macOS will
/// say, otherwise something recognisable rather than clever.
pub fn suggested_name(fingerprint: &Fingerprint) -> String {
    if !fingerprint.ssid.is_empty() {
        return fingerprint.ssid.clone();
    }
    let vendor = crate::vendor::lookup(&fingerprint.gateway_mac);
    if !vendor.is_empty() {
        return format!("{vendor} network");
    }
    if !fingerprint.gateway_ip.is_empty() {
        return format!("Network at {}", fingerprint.gateway_ip);
    }
    "This network".into()
}

/// The value after a label in `route -n get default` output.
fn field(output: &str, label: &str) -> String {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

async fn ssid(interface: &str) -> String {
    if interface.is_empty() || !cfg!(target_os = "macos") {
        return String::new();
    }
    let summary = scanner::run("ipconfig", &["getsummary", interface]).await;
    let ssid = summary
        .lines()
        .find_map(|line| line.trim().strip_prefix("SSID : "))
        .unwrap_or_default()
        .trim()
        .to_string();
    // Without Location Services macOS answers "<redacted>".
    if ssid.starts_with('<') {
        return String::new();
    }
    ssid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_default_route() {
        let output = "   route to: default\ndestination: default\n       gateway: 192.168.1.1\n \
                      interface: en0\n     flags: <UP,GATEWAY,DONE,STATIC>\n";
        assert_eq!(field(output, "gateway:"), "192.168.1.1");
        assert_eq!(field(output, "interface:"), "en0");
        assert_eq!(field(output, "nonsense:"), "");
    }

    #[test]
    fn names_a_network_as_helpfully_as_it_can() {
        let mut fingerprint = Fingerprint {
            gateway_ip: "192.168.1.1".into(),
            gateway_mac: "AC:F8:CC:8A:1E:46".into(),
            ..Default::default()
        };
        assert_eq!(suggested_name(&fingerprint), "Commscope network");

        fingerprint.ssid = "Bletchley".into();
        assert_eq!(
            suggested_name(&fingerprint),
            "Bletchley",
            "its own name wins"
        );

        let unknown = Fingerprint {
            gateway_ip: "10.0.0.1".into(),
            ..Default::default()
        };
        assert_eq!(suggested_name(&unknown), "Network at 10.0.0.1");
        assert_eq!(suggested_name(&Fingerprint::default()), "This network");
    }
}
