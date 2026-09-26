//! Passive-ish discovery: ask the network to introduce itself.
//!
//! Two multicast questions, answered by devices that may ignore ping entirely
//! and have no scanned port open - and the answers carry a real name and a
//! device type, which reverse DNS rarely does.

use crate::dns::{self, Record};
use crate::fdlimit;
use crate::scanner::Cancel;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout_at, Instant};

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

/// Service types worth asking about by name. The meta-query below finds the
/// rest, but naming these gets answers from devices that ignore it.
const SERVICE_TYPES: &[&str] = &[
    "_services._dns-sd._udp.local", // "what services exist?"
    "_airplay._tcp.local",
    "_raop._tcp.local", // AirPlay audio
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_printer._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_homekit._tcp.local",
    "_hap._tcp.local",
    "_device-info._tcp.local",
    "_workstation._tcp.local",
    "_companion-link._tcp.local",
    "_rdlink._tcp.local",
    "_nvstream._tcp.local", // NVIDIA Shield
    "_esphomelib._tcp.local",
    "_miio._udp.local", // Xiaomi
];

/// What a device said about itself.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Announcement {
    /// Friendly host name, without the trailing ".local".
    pub name: String,
    /// Human-readable service or device descriptions.
    pub services: Vec<String>,
}

pub type Announcements = BTreeMap<Ipv4Addr, Announcement>;

/// Listen for `window`, then return what answered. Runs both protocols at once.
pub async fn discover(window: Duration, cancel: &Cancel) -> Announcements {
    let deadline = Instant::now() + window;
    let (mdns, ssdp) = tokio::join!(mdns(deadline, cancel), ssdp(deadline, cancel));
    let mut found = mdns;
    for (ip, announcement) in ssdp {
        let entry = found.entry(ip).or_default();
        if entry.name.is_empty() {
            entry.name = announcement.name;
        }
        entry.services.extend(announcement.services);
    }
    for announcement in found.values_mut() {
        announcement.services.sort();
        announcement.services.dedup();
    }
    found
}

// --------------------------------------------------------------------------
// mDNS
// --------------------------------------------------------------------------

async fn mdns(deadline: Instant, cancel: &Cancel) -> Announcements {
    let mut found = Announcements::new();
    let Some(socket) = mdns_socket().await else {
        return found;
    };

    let target = SocketAddr::from(SocketAddrV4::new(MDNS_GROUP, MDNS_PORT));
    // Ask for the unicast reply, since binding 5353 may not have worked.
    for types in SERVICE_TYPES.chunks(8) {
        let query = dns::query(types, dns::TYPE_PTR, true);
        let _ = socket.send_to(&query, target).await;
    }

    // Names arrive in separate records from addresses, so collect both and
    // join them at the end: hostname -> services, hostname -> ip.
    let mut services: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut addresses: BTreeMap<String, Ipv4Addr> = BTreeMap::new();
    let mut instances: BTreeMap<String, String> = BTreeMap::new(); // instance -> host

    let mut buf = vec![0u8; 4096];
    while let Ok(Ok((n, from))) = timeout_at(deadline, socket.recv_from(&mut buf)).await {
        if cancel.is_cancelled() {
            break;
        }
        let SocketAddr::V4(from) = from else { continue };
        for record in dns::parse_records(&buf[..n]) {
            match record {
                Record::A { name, ip } => {
                    addresses.insert(name, ip);
                }
                Record::Srv { name, host, .. } => {
                    instances.insert(name, host);
                }
                Record::Ptr { name, target } => {
                    if let Some(label) = service_label(&name) {
                        services.entry(target).or_default().push(label);
                    }
                }
                Record::Txt { .. } => {}
            }
        }
        // The sender is the device itself, so its address is known even when
        // no A record turned up.
        found.entry(*from.ip()).or_default();
    }

    for (instance, services) in services {
        // "Study Printer._ipp._tcp.local" -> host via SRV, else the instance name.
        let host = instances.get(&instance).cloned().unwrap_or_default();
        let Some(ip) = addresses.get(&host).or_else(|| addresses.get(&instance)) else {
            continue;
        };
        let entry = found.entry(*ip).or_default();
        if entry.name.is_empty() {
            entry.name = friendly(&host)
                .or_else(|| instance_name(&instance))
                .unwrap_or_default();
        }
        entry.services.extend(services);
    }
    for (host, ip) in addresses {
        let entry = found.entry(ip).or_default();
        if entry.name.is_empty() {
            entry.name = friendly(&host).unwrap_or_default();
        }
    }
    found
}

/// An ephemeral port, deliberately: macOS runs mDNSResponder on 5353, and
/// sharing that port means the replies are delivered to it rather than to us.
/// Asking for unicast answers (the QU bit) keeps them coming back here.
async fn mdns_socket() -> Option<UdpSocket> {
    let _fds = fdlimit::acquire(fdlimit::SOCKET).await;
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    let any = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    socket.bind(&SocketAddr::from(any).into()).ok()?;
    // Send from the LAN interface, not whatever the default route is (a VPN
    // tunnel, say), and with the TTL the spec demands: responders drop the rest.
    if let Some(local) = crate::scanner::local_ip() {
        let _ = socket.set_multicast_if_v4(&local);
    }
    let _ = socket.set_multicast_ttl_v4(255);
    socket.set_nonblocking(true).ok()?;
    UdpSocket::from_std(socket.into()).ok()
}

/// "Study Printer._ipp._tcp.local" -> "Study Printer"
fn instance_name(instance: &str) -> Option<String> {
    let name = instance.split("._").next()?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// "nas.local" -> "nas"
fn friendly(host: &str) -> Option<String> {
    let name = host
        .trim_end_matches('.')
        .strip_suffix(".local")
        .unwrap_or(host);
    (!name.is_empty() && !name.contains("._")).then(|| name.to_string())
}

/// A readable name for a service type, from either a PTR name or an instance.
fn service_label(service_type: &str) -> Option<String> {
    let key = service_type.split('.').find(|part| part.starts_with('_'))?;
    Some(
        match key {
            "_airplay" | "_raop" => "AirPlay",
            "_googlecast" => "Chromecast",
            "_spotify-connect" => "Spotify Connect",
            "_printer" | "_ipp" | "_ipps" | "_pdl-datastream" => "Printer",
            "_smb" | "_afpovertcp" => "File sharing",
            "_ssh" | "_sftp-ssh" => "SSH",
            "_http" | "_https" => "Web interface",
            "_homekit" | "_hap" => "HomeKit",
            "_device-info" | "_workstation" => "Computer",
            "_companion-link" | "_rdlink" => "Apple device",
            "_nvstream" => "NVIDIA Shield",
            "_esphomelib" => "ESPHome",
            "_miio" => "Xiaomi",
            "_services" | "_dns-sd" => return None,
            other => return Some(other.trim_start_matches('_').to_string()),
        }
        .to_string(),
    )
}

// --------------------------------------------------------------------------
// SSDP / UPnP
// --------------------------------------------------------------------------

async fn ssdp(deadline: Instant, cancel: &Cancel) -> Announcements {
    let mut found = Announcements::new();
    let _fds = fdlimit::acquire(fdlimit::SOCKET).await;
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return found;
    };

    let search = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_GROUP}:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\n\
         MX: 2\r\nST: ssdp:all\r\nUSER-AGENT: VeryAnnoyedIPScanner/0.1\r\n\r\n"
    );
    let target = SocketAddr::from(SocketAddrV4::new(SSDP_GROUP, SSDP_PORT));
    let _ = socket.send_to(search.as_bytes(), target).await;

    let mut buf = vec![0u8; 4096];
    while let Ok(Ok((n, from))) = timeout_at(deadline, socket.recv_from(&mut buf)).await {
        if cancel.is_cancelled() {
            break;
        }
        let SocketAddr::V4(from) = from else { continue };
        let entry = found.entry(*from.ip()).or_default();
        let announcement = parse_ssdp(&String::from_utf8_lossy(&buf[..n]));
        if entry.name.is_empty() {
            entry.name = announcement.name;
        }
        entry.services.extend(announcement.services);
    }
    found
}

/// Pull the interesting headers out of an SSDP response.
fn parse_ssdp(response: &str) -> Announcement {
    let mut announcement = Announcement::default();
    for line in response.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_uppercase().as_str() {
            "SERVER" => {
                if let Some(product) = ssdp_product(value) {
                    announcement.services.push(format!("UPnP: {product}"));
                }
            }
            "ST" | "NT" => {
                if let Some(kind) = upnp_device_type(value) {
                    announcement.services.push(kind);
                }
            }
            _ => {}
        }
    }
    announcement
}

/// "urn:schemas-upnp-org:device:MediaRenderer:1" -> "MediaRenderer".
/// Generic types say nothing worth showing.
fn upnp_device_type(urn: &str) -> Option<String> {
    const USELESS: &[&str] = &[
        "Basic",
        "WANDevice",
        "WANConnectionDevice",
        "InternetGatewayDevice",
    ];
    let kind = urn.split(':').nth(3).filter(|_| urn.contains(":device:"))?;
    if USELESS.contains(&kind) || kind.is_empty() {
        return None;
    }
    // Vendor URNs use lower case for things like "tv".
    Some(if kind.len() <= 3 {
        kind.to_uppercase()
    } else {
        kind.to_string()
    })
}

/// The product out of a SERVER header: "Linux/4.4 UPnP/1.0 Sonos/80.1-52020"
/// -> "Sonos/80.1-52020". The OS and protocol versions aren't interesting.
fn ssdp_product(server: &str) -> Option<String> {
    const BORING: &[&str] = &[
        "upnp", "linux", "unix", "windows", "darwin", "posix", "http",
    ];
    server
        .split_whitespace()
        .rfind(|token| {
            let Some((name, version)) = token.split_once('/') else {
                return false;
            };
            // A real version number, so placeholders like "TV/Version" don't count.
            version.starts_with(|c: char| c.is_ascii_digit())
                && !BORING.contains(&name.to_ascii_lowercase().as_str())
        })
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_service_types() {
        assert_eq!(
            service_label("_airplay._tcp.local").as_deref(),
            Some("AirPlay")
        );
        assert_eq!(
            service_label("Study._ipp._tcp.local").as_deref(),
            Some("Printer")
        );
        assert_eq!(service_label("_services._dns-sd._udp.local"), None);
        // Unknown types still say something rather than nothing.
        assert_eq!(service_label("_weird._tcp.local").as_deref(), Some("weird"));
    }

    #[test]
    fn extracts_names() {
        assert_eq!(friendly("nas.local").as_deref(), Some("nas"));
        assert_eq!(friendly("Study Printer._ipp._tcp.local"), None);
        assert_eq!(
            instance_name("Study Printer._ipp._tcp.local").as_deref(),
            Some("Study Printer")
        );
    }

    #[test]
    fn reads_an_ssdp_response() {
        let response = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n\
                        LOCATION: http://192.168.0.30:1400/xml/device_description.xml\r\n\
                        SERVER: Linux/4.4 UPnP/1.0 Sonos/80.1-52020\r\n\
                        ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n";
        let announcement = parse_ssdp(response);
        assert_eq!(
            announcement.services,
            ["UPnP: Sonos/80.1-52020", "ZonePlayer"]
        );
    }

    #[test]
    fn skips_noise_in_ssdp() {
        // Service URNs, and device types that describe every router alike.
        assert_eq!(
            upnp_device_type("urn:schemas-upnp-org:service:AVTransport:1"),
            None
        );
        assert_eq!(upnp_device_type("upnp:rootdevice"), None);
        assert_eq!(
            upnp_device_type("urn:schemas-upnp-org:device:Basic:1"),
            None
        );
        assert_eq!(
            upnp_device_type("urn:lge-com:device:tv:1").as_deref(),
            Some("TV")
        );
        // SERVER headers made only of OS and protocol versions.
        assert_eq!(ssdp_product("Linux/4.4 UPnP/1.0"), None);
        assert_eq!(ssdp_product("UPnP/1.0 0.9"), None);
        assert_eq!(ssdp_product("TV/Version UPnP/1.0"), None); // not a version
        assert_eq!(
            ssdp_product("Linux UPnP/1.0 webOSTV/1.0").as_deref(),
            Some("webOSTV/1.0")
        );
    }
}
