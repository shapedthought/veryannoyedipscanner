//! Just enough DNS to build mDNS queries and read the answers.
//!
//! mDNS is DNS on a multicast address, so this is a small reader for the
//! record types that identify a device: A (address), PTR (service instances),
//! SRV (host behind a service) and TXT (model, in a few useful cases).

use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;
/// Top bit of the class field: "please answer me directly". Without it a
/// responder multicasts, which we'd only see while bound to port 5353.
const UNICAST_RESPONSE: u16 = 0x8000;
/// Compression: the two high bits of a length byte mark a pointer.
const POINTER: u8 = 0xc0;

#[derive(Debug, PartialEq)]
pub enum Record {
    A {
        name: String,
        ip: Ipv4Addr,
    },
    Ptr {
        name: String,
        target: String,
    },
    Srv {
        name: String,
        host: String,
        port: u16,
    },
    Txt {
        name: String,
        values: Vec<String>,
    },
}

/// A query for each name, in one packet.
pub fn query(names: &[&str], record_type: u16, unicast: bool) -> Vec<u8> {
    let mut packet = vec![0u8; 12];
    packet[5] = names.len() as u8; // question count; id and flags stay zero
    let class = if unicast {
        CLASS_IN | UNICAST_RESPONSE
    } else {
        CLASS_IN
    };
    for name in names {
        write_name(&mut packet, name);
        packet.extend_from_slice(&record_type.to_be_bytes());
        packet.extend_from_slice(&class.to_be_bytes());
    }
    packet
}

fn write_name(packet: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
}

/// Read every answer in a response, ignoring anything malformed.
pub fn parse_records(packet: &[u8]) -> Vec<Record> {
    let mut records = Vec::new();
    let Some(counts) = Counts::read(packet) else {
        return records;
    };
    let mut at = 12;

    for _ in 0..counts.questions {
        let Some(next) = skip_name(packet, at) else {
            return records;
        };
        at = next + 4; // type + class
    }
    for _ in 0..counts.answers() {
        let Some((name, next)) = read_name(packet, at) else {
            return records;
        };
        at = next;
        if at + 10 > packet.len() {
            return records;
        }
        let record_type = u16::from_be_bytes([packet[at], packet[at + 1]]);
        let length = u16::from_be_bytes([packet[at + 8], packet[at + 9]]) as usize;
        at += 10;
        let Some(data) = packet.get(at..at + length) else {
            return records;
        };
        if let Some(record) = read_record(packet, name, record_type, data, at) {
            records.push(record);
        }
        at += length;
    }
    records
}

struct Counts {
    questions: u16,
    answers: u16,
    authority: u16,
    additional: u16,
}

impl Counts {
    fn read(packet: &[u8]) -> Option<Self> {
        let header: &[u8; 12] = packet.get(..12)?.try_into().ok()?;
        let n = |at: usize| u16::from_be_bytes([header[at], header[at + 1]]);
        Some(Self {
            questions: n(4),
            answers: n(6),
            authority: n(8),
            additional: n(10),
        })
    }

    /// Responders put the useful records (A, SRV, TXT) in the additional
    /// section as often as in the answer section.
    fn answers(&self) -> u32 {
        u32::from(self.answers) + u32::from(self.authority) + u32::from(self.additional)
    }
}

fn read_record(
    packet: &[u8],
    name: String,
    record_type: u16,
    data: &[u8],
    at: usize,
) -> Option<Record> {
    match record_type {
        TYPE_A if data.len() == 4 => Some(Record::A {
            name,
            ip: Ipv4Addr::new(data[0], data[1], data[2], data[3]),
        }),
        TYPE_PTR => Some(Record::Ptr {
            name,
            target: read_name(packet, at)?.0,
        }),
        TYPE_SRV if data.len() > 6 => Some(Record::Srv {
            name,
            port: u16::from_be_bytes([data[4], data[5]]),
            host: read_name(packet, at + 6)?.0,
        }),
        TYPE_TXT => Some(Record::Txt {
            name,
            values: read_txt(data),
        }),
        _ => None,
    }
}

/// TXT data is a sequence of length-prefixed strings.
fn read_txt(mut data: &[u8]) -> Vec<String> {
    let mut values = Vec::new();
    while let Some((&length, rest)) = data.split_first() {
        let length = length as usize;
        if rest.len() < length {
            break;
        }
        if length > 0 {
            values.push(String::from_utf8_lossy(&rest[..length]).into_owned());
        }
        data = &rest[length..];
    }
    values
}

/// Read a name, following compression pointers. Returns the name and the
/// offset just past it in the *packet* (pointers don't advance the reader).
fn read_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut at = start;
    let mut after_pointer = None;
    // A malformed packet can point in circles; every jump must move backwards,
    // which bounds the work.
    let mut limit = packet.len();

    loop {
        limit = limit.checked_sub(1)?;
        match *packet.get(at)? {
            0 => {
                let end = after_pointer.unwrap_or(at + 1);
                return Some((labels.join("."), end));
            }
            length if length & POINTER == POINTER => {
                let target = usize::from(u16::from_be_bytes([length & 0x3f, *packet.get(at + 1)?]));
                after_pointer.get_or_insert(at + 2);
                if target >= at {
                    return None; // forward or self pointer: refuse to loop
                }
                at = target;
            }
            length => {
                let from = at + 1;
                let label = packet.get(from..from + length as usize)?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                at = from + length as usize;
            }
        }
    }
}

fn skip_name(packet: &[u8], at: usize) -> Option<usize> {
    read_name(packet, at).map(|(_, end)| end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        write_name(&mut out, name);
        out
    }

    #[test]
    fn builds_a_query() {
        let packet = query(&["_airplay._tcp.local"], TYPE_PTR, true);
        assert_eq!(packet[4..6], [0, 1], "one question");
        assert_eq!(&packet[12..12 + 9], b"\x08_airplay");
        let tail = &packet[packet.len() - 4..];
        assert_eq!(tail, [0, 12, 0x80, 1], "PTR, class IN with the unicast bit");
    }

    /// Answer section: A record for "nas.local", plus a PTR whose name uses a
    /// compression pointer back to it.
    fn response() -> Vec<u8> {
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        let name_at = p.len();
        p.extend(name_bytes("nas.local"));
        p.extend([0, 1, 0, 1, 0, 0, 0, 120, 0, 4]); // A, IN, ttl, length
        p.extend([192, 168, 0, 10]);
        p.extend([POINTER, name_at as u8]); // pointer to "nas.local"
        p.extend([0, 12, 0, 1, 0, 0, 0, 120]);
        let target = name_bytes("Study Printer._ipp._tcp.local");
        p.extend((target.len() as u16).to_be_bytes());
        p.extend(target);
        p
    }

    #[test]
    fn reads_records_and_follows_compression() {
        let records = parse_records(&response());
        assert_eq!(
            records,
            vec![
                Record::A {
                    name: "nas.local".into(),
                    ip: "192.168.0.10".parse().unwrap()
                },
                Record::Ptr {
                    name: "nas.local".into(),
                    target: "Study Printer._ipp._tcp.local".into(),
                },
            ]
        );
    }

    #[test]
    fn reads_srv_and_txt() {
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        p.extend(name_bytes("hub._hap._tcp.local"));
        p.extend([0, 33, 0, 1, 0, 0, 0, 120]);
        let mut srv = vec![0, 0, 0, 0, 0x1f, 0x90]; // priority, weight, port 8080
        srv.extend(name_bytes("hub.local"));
        p.extend((srv.len() as u16).to_be_bytes());
        p.extend(srv);
        p.extend(name_bytes("hub._hap._tcp.local"));
        p.extend([0, 16, 0, 1, 0, 0, 0, 120]);
        let txt = b"\x0amd=Hub One\x07ff=1234".to_vec(); // length-prefixed strings
        p.extend((txt.len() as u16).to_be_bytes());
        p.extend(txt);

        assert_eq!(
            parse_records(&p),
            vec![
                Record::Srv {
                    name: "hub._hap._tcp.local".into(),
                    host: "hub.local".into(),
                    port: 8080,
                },
                Record::Txt {
                    name: "hub._hap._tcp.local".into(),
                    values: vec!["md=Hub One".into(), "ff=1234".into()],
                },
            ]
        );
    }

    #[test]
    fn survives_rubbish() {
        assert!(parse_records(&[]).is_empty());
        assert!(parse_records(&[0; 12]).is_empty());
        // Truncated mid-record, and a pointer that would loop forever.
        let good = response();
        assert!(parse_records(&good[..good.len() - 5]).len() <= 1);
        let mut loopy = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        loopy.extend([POINTER, 12, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 1, 2, 3, 4]);
        assert!(parse_records(&loopy).is_empty());
    }
}
