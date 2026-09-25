//! Pinging over an unprivileged ICMP datagram socket.
//!
//! macOS and Linux both allow SOCK_DGRAM/IPPROTO_ICMP without root, so we can
//! ping without shelling out to `ping` - one socket and one reader task for the
//! whole scan, instead of a process (and four descriptors) per host.
//!
//! Where the socket isn't permitted (some Linux setups restrict it to a group
//! range), `open()` fails and the caller falls back to the `ping` binary.

use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;
const HEADER: usize = 8;
/// Marks a packet as ours, since replies to other pingers can't be told apart
/// by identifier alone (Linux rewrites it, macOS doesn't).
const MAGIC: [u8; 4] = *b"VAIS";
const PAYLOAD: usize = MAGIC.len() + 2; // magic + sequence

type Pending = Arc<Mutex<HashMap<u16, oneshot::Sender<Instant>>>>;

pub struct Pinger {
    socket: Arc<Socket>,
    sequence: AtomicU16,
    pending: Pending,
}

/// The process-wide pinger, or None if the socket couldn't be opened.
pub fn shared() -> Option<&'static Arc<Pinger>> {
    static PINGER: OnceLock<Option<Arc<Pinger>>> = OnceLock::new();
    PINGER
        .get_or_init(|| match Pinger::open() {
            Ok(p) => {
                let pinger = Arc::new(p);
                // A plain thread, not a task: the reader must outlive any one
                // runtime, and blocking recv needs no reactor.
                let reader = pinger.clone();
                std::thread::Builder::new()
                    .name("icmp-reader".into())
                    .spawn(move || read_replies(&reader))
                    .expect("spawn ICMP reader thread");
                Some(pinger)
            }
            Err(e) => {
                eprintln!("ICMP socket unavailable ({e}); falling back to the ping command");
                None
            }
        })
        .as_ref()
}

impl Pinger {
    fn open() -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        Ok(Self {
            socket: Arc::new(socket),
            sequence: AtomicU16::new(0),
            pending: Pending::default(),
        })
    }

    /// Send one echo request and wait for its reply. None means no answer
    /// within `timeout`.
    pub async fn ping(&self, ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().ok()?.insert(sequence, tx);

        let sent = Instant::now();
        let result = match self.send(ip, sequence) {
            Ok(()) => match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(at)) => Some(at.duration_since(sent).as_secs_f64() * 1000.0),
                _ => None,
            },
            Err(_) => None,
        };
        // On timeout or error nobody consumed the slot, so clear it.
        self.pending.lock().ok()?.remove(&sequence);
        result
    }

    /// Echo requests are tiny and the socket buffer is generous, so this
    /// doesn't block in practice.
    fn send(&self, ip: Ipv4Addr, sequence: u16) -> io::Result<()> {
        let addr: SocketAddr = SocketAddrV4::new(ip, 0).into();
        self.socket
            .send_to(&echo_request(sequence), &addr.into())
            .map(|_| ())
    }
}

/// One thread drains the socket for the whole process and wakes whoever is
/// waiting on each sequence number.
fn read_replies(pinger: &Pinger) {
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let n = match pinger.socket.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        // SAFETY: recv reported n initialised bytes at the front of buf.
        let packet = unsafe { &*(&buf[..n] as *const [std::mem::MaybeUninit<u8>] as *const [u8]) };
        let Some(sequence) = reply_sequence(packet) else {
            continue;
        };
        if let Ok(mut pending) = pinger.pending.lock() {
            if let Some(tx) = pending.remove(&sequence) {
                let _ = tx.send(Instant::now());
            }
        }
    }
}

fn echo_request(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0u8; HEADER + PAYLOAD];
    packet[0] = ECHO_REQUEST;
    // [1] code, [2..4] checksum, [4..6] identifier: the kernel may rewrite the
    // identifier, so the payload carries what we match on.
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    packet[HEADER..HEADER + 4].copy_from_slice(&MAGIC);
    packet[HEADER + 4..HEADER + 6].copy_from_slice(&sequence.to_be_bytes());
    let sum = checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// The sequence number of an echo reply of ours, if that's what this is.
fn reply_sequence(packet: &[u8]) -> Option<u16> {
    // Raw sockets hand back the IP header; datagram sockets usually don't.
    let icmp = match packet.first() {
        Some(&b) if b >> 4 == 4 && packet.len() > 20 => &packet[((b & 0x0f) as usize * 4)..],
        _ => packet,
    };
    if icmp.len() < HEADER + PAYLOAD || icmp[0] != ECHO_REPLY {
        return None;
    }
    let payload = &icmp[HEADER..];
    if payload[..4] != MAGIC {
        return None;
    }
    Some(u16::from_be_bytes([payload[4], payload[5]]))
}

/// Standard internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = remainder {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_known_packet() {
        // Echo request, id 1, seq 9, "abc" payload; odd length exercises the
        // trailing-byte path. Sum: 0800+0001+0009+6162+6300 = cc6c -> !cc6c = 3393.
        let packet = [8u8, 0, 0x33, 0x93, 0, 1, 0, 9, b'a', b'b', b'c'];
        let mut zeroed = packet;
        zeroed[2] = 0;
        zeroed[3] = 0;
        assert_eq!(
            checksum(&zeroed),
            u16::from_be_bytes([packet[2], packet[3]])
        );
        // A packet including its own checksum sums to zero.
        assert_eq!(checksum(&packet), 0);
    }

    #[test]
    fn recognises_only_our_replies() {
        let mut reply = echo_request(42);
        reply[0] = ECHO_REPLY;
        assert_eq!(reply_sequence(&reply), Some(42));

        // Same packet behind an IP header (raw-socket style).
        let mut with_ip = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        with_ip.extend_from_slice(&reply);
        assert_eq!(reply_sequence(&with_ip), Some(42));

        // Someone else's ping, and our own outgoing request.
        let mut foreign = reply.clone();
        foreign[HEADER..HEADER + 4].copy_from_slice(b"XXXX");
        assert_eq!(reply_sequence(&foreign), None);
        assert_eq!(reply_sequence(&echo_request(42)), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pings_over_the_socket() {
        let Some(pinger) = shared() else {
            eprintln!("no ICMP socket here; skipping");
            return;
        };
        let rtt = pinger
            .ping(Ipv4Addr::LOCALHOST, Duration::from_secs(2))
            .await;
        assert!(rtt.is_some(), "loopback should answer an echo request");

        let unused: Ipv4Addr = "192.0.2.1".parse().unwrap(); // TEST-NET-1, never answers
        assert_eq!(pinger.ping(unused, Duration::from_millis(300)).await, None);

        // Neither the answered nor the timed-out ping may leave a slot behind.
        assert!(pinger.pending.lock().unwrap().is_empty());
    }
}
