//! Scan history in SQLite, and diffing two scans to see what changed.

use crate::scanner::HostResult;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

pub struct Db(pub Mutex<Connection>);

impl Db {
    pub fn conn(&self) -> Result<MutexGuard<'_, Connection>, String> {
        self.0.lock().map_err(|e| format!("History database lock poisoned: {e}"))
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct ScanSummary {
    pub id: i64,
    pub started_at: i64,
    pub finished_at: i64,
    pub range_start: String,
    pub range_end: String,
    pub ports: Vec<u16>,
    pub total: i64,
    pub alive: i64,
}

#[derive(Serialize)]
pub struct SavedScan {
    pub summary: ScanSummary,
    pub hosts: Vec<HostResult>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Change {
    pub host: HostResult,
    /// Set when the device (matched by MAC) now answers on a different IP.
    pub old_ip: Option<String>,
    /// Set when the same IP now belongs to a different MAC.
    pub old_mac: Option<String>,
    pub old_hostname: Option<String>,
    pub opened: Vec<u16>,
    pub closed: Vec<u16>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Diff {
    pub old: ScanSummary,
    pub new: ScanSummary,
    pub added: Vec<HostResult>,
    pub gone: Vec<HostResult>,
    pub changed: Vec<Change>,
}

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS scans (
             id          INTEGER PRIMARY KEY,
             started_at  INTEGER NOT NULL,
             finished_at INTEGER NOT NULL,
             range_start TEXT NOT NULL,
             range_end   TEXT NOT NULL,
             ports       TEXT NOT NULL,
             total       INTEGER NOT NULL,
             alive       INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS hosts (
             scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
             ip      TEXT NOT NULL,
             data    TEXT NOT NULL,
             PRIMARY KEY (scan_id, ip)
         );",
    )?;
    Ok(conn)
}

/// Persist a finished scan. Only live hosts are stored; dead ones are implied
/// by the range.
pub fn save(conn: &mut Connection, summary: &ScanSummary, hosts: &[HostResult]) -> rusqlite::Result<i64> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO scans (started_at, finished_at, range_start, range_end, ports, total, alive)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            summary.started_at,
            summary.finished_at,
            summary.range_start,
            summary.range_end,
            serde_json::to_string(&summary.ports).unwrap(),
            summary.total,
            summary.alive,
        ],
    )?;
    let id = tx.last_insert_rowid();
    {
        let mut stmt = tx.prepare("INSERT INTO hosts (scan_id, ip, data) VALUES (?1, ?2, ?3)")?;
        for host in hosts.iter().filter(|h| h.alive) {
            stmt.execute(params![id, host.ip, serde_json::to_string(host).unwrap()])?;
        }
    }
    tx.commit()?;
    Ok(id)
}

fn summary_from_row(row: &rusqlite::Row) -> rusqlite::Result<ScanSummary> {
    let ports: String = row.get(5)?;
    Ok(ScanSummary {
        id: row.get(0)?,
        started_at: row.get(1)?,
        finished_at: row.get(2)?,
        range_start: row.get(3)?,
        range_end: row.get(4)?,
        ports: serde_json::from_str(&ports).unwrap_or_default(),
        total: row.get(6)?,
        alive: row.get(7)?,
    })
}

const SUMMARY_COLS: &str = "id, started_at, finished_at, range_start, range_end, ports, total, alive";

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<ScanSummary>> {
    let mut stmt = conn.prepare(&format!("SELECT {SUMMARY_COLS} FROM scans ORDER BY id DESC"))?;
    let rows = stmt.query_map([], summary_from_row)?;
    rows.collect()
}

pub fn load(conn: &Connection, id: i64) -> rusqlite::Result<SavedScan> {
    let summary = conn.query_row(
        &format!("SELECT {SUMMARY_COLS} FROM scans WHERE id = ?1"),
        [id],
        summary_from_row,
    )?;
    let mut stmt = conn.prepare("SELECT data FROM hosts WHERE scan_id = ?1")?;
    let mut hosts: Vec<HostResult> = stmt
        .query_map([id], |row| row.get::<_, String>(0))?
        .filter_map(|data| data.ok().and_then(|d| serde_json::from_str(&d).ok()))
        .collect();
    hosts.sort_by_key(|h| ip_num(&h.ip));
    Ok(SavedScan { summary, hosts })
}

pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM scans WHERE id = ?1", [id])?;
    Ok(())
}

/// The most recent earlier scan of exactly the same range, used as the
/// automatic baseline for "what changed since last time".
pub fn baseline_for(conn: &Connection, scan: &ScanSummary) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM scans WHERE range_start = ?1 AND range_end = ?2 AND id < ?3
         ORDER BY id DESC LIMIT 1",
        params![scan.range_start, scan.range_end, scan.id],
        |row| row.get(0),
    )
    .optional()
}

// --------------------------------------------------------------------------
// Diffing
// --------------------------------------------------------------------------

fn ip_num(ip: &str) -> u32 {
    ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0)
}

fn in_range(ip: &str, scan: &ScanSummary) -> bool {
    let (a, b) = (ip_num(&scan.range_start), ip_num(&scan.range_end));
    (a.min(b)..=a.max(b)).contains(&ip_num(ip))
}

/// MACs that identify exactly one host in a scan. Routers doing proxy ARP can
/// answer for many IPs with one MAC, so those can't be used to match.
fn unique_macs(hosts: &[HostResult]) -> HashMap<&str, usize> {
    let mut counts: HashMap<&str, (usize, usize)> = HashMap::new();
    for (i, h) in hosts.iter().enumerate().filter(|(_, h)| !h.mac.is_empty()) {
        counts.entry(h.mac.as_str()).or_insert((0, i)).0 += 1;
    }
    counts.into_iter().filter(|(_, (n, _))| *n == 1).map(|(m, (_, i))| (m, i)).collect()
}

/// Compare two scans. Hosts are matched by MAC first (so a device that
/// changed IP is "moved", not "gone + new"), then by IP.
pub fn diff(old: &SavedScan, new: &SavedScan) -> Diff {
    let (o, n) = (&old.hosts, &new.hosts);
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    let mut old_used = vec![false; o.len()];
    let mut new_used = vec![false; n.len()];

    let old_macs = unique_macs(o);
    for (&mac, &ni) in &unique_macs(n) {
        if let Some(&oi) = old_macs.get(mac) {
            pairs.push((oi, ni));
            old_used[oi] = true;
            new_used[ni] = true;
        }
    }
    let old_by_ip: HashMap<&str, usize> =
        o.iter().enumerate().filter(|(i, _)| !old_used[*i]).map(|(i, h)| (h.ip.as_str(), i)).collect();
    for (ni, h) in n.iter().enumerate() {
        if new_used[ni] {
            continue;
        }
        if let Some(&oi) = old_by_ip.get(h.ip.as_str()) {
            pairs.push((oi, ni));
            old_used[oi] = true;
            new_used[ni] = true;
        }
    }

    // Only compare ports both scans actually probed.
    let scanned: BTreeSet<u16> = old.summary.ports.iter().copied()
        .filter(|p| new.summary.ports.contains(p))
        .collect();
    let mut changed: Vec<Change> = pairs
        .into_iter()
        .filter_map(|(oi, ni)| {
            let (a, b) = (&o[oi], &n[ni]);
            let pa: BTreeSet<u16> = a.ports.iter().copied().filter(|p| scanned.contains(p)).collect();
            let pb: BTreeSet<u16> = b.ports.iter().copied().filter(|p| scanned.contains(p)).collect();
            let change = Change {
                host: b.clone(),
                old_ip: (a.ip != b.ip).then(|| a.ip.clone()),
                old_mac: (!a.mac.is_empty() && !b.mac.is_empty() && a.mac != b.mac).then(|| a.mac.clone()),
                // Reverse DNS is flaky, so only report a rename, not a blank.
                old_hostname: (!a.hostname.is_empty() && !b.hostname.is_empty() && a.hostname != b.hostname)
                    .then(|| a.hostname.clone()),
                opened: pb.difference(&pa).copied().collect(),
                closed: pa.difference(&pb).copied().collect(),
            };
            let any = change.old_ip.is_some()
                || change.old_mac.is_some()
                || change.old_hostname.is_some()
                || !change.opened.is_empty()
                || !change.closed.is_empty();
            any.then_some(change)
        })
        .collect();
    changed.sort_by_key(|c| ip_num(&c.host.ip));

    // When comparing different ranges, ignore hosts the other scan never looked at.
    let added = n.iter().enumerate()
        .filter(|(i, h)| !new_used[*i] && in_range(&h.ip, &old.summary))
        .map(|(_, h)| h.clone())
        .collect();
    let gone = o.iter().enumerate()
        .filter(|(i, h)| !old_used[*i] && in_range(&h.ip, &new.summary))
        .map(|(_, h)| h.clone())
        .collect();

    Diff { old: old.summary.clone(), new: new.summary.clone(), added, gone, changed }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str, mac: &str, ports: &[u16]) -> HostResult {
        HostResult {
            ip: ip.into(),
            alive: true,
            mac: mac.into(),
            ports: ports.to_vec(),
            ..Default::default()
        }
    }

    fn scan(id: i64, hosts: Vec<HostResult>) -> SavedScan {
        SavedScan {
            summary: ScanSummary {
                id,
                started_at: 0,
                finished_at: 0,
                range_start: "10.0.0.1".into(),
                range_end: "10.0.0.254".into(),
                ports: vec![22, 80, 443],
                total: 254,
                alive: hosts.len() as i64,
            },
            hosts,
        }
    }

    #[test]
    fn detects_every_kind_of_change() {
        let old = scan(1, vec![
            host("10.0.0.1", "AA:00:00:00:00:01", &[80]),        // router, unchanged
            host("10.0.0.2", "AA:00:00:00:00:02", &[22]),        // gets 443 opened, 22 closed
            host("10.0.0.3", "AA:00:00:00:00:03", &[]),          // moves to .30
            host("10.0.0.4", "AA:00:00:00:00:04", &[]),          // disappears
            host("10.0.0.5", "AA:00:00:00:00:05", &[]),          // IP taken over by new MAC
        ]);
        let new = scan(2, vec![
            host("10.0.0.1", "AA:00:00:00:00:01", &[80, 8080]),  // 8080 wasn't scanned before
            host("10.0.0.2", "AA:00:00:00:00:02", &[443]),
            host("10.0.0.30", "AA:00:00:00:00:03", &[]),
            host("10.0.0.5", "BB:00:00:00:00:05", &[]),
            host("10.0.0.9", "", &[22]),                         // brand new
        ]);
        let d = diff(&old, &new);

        assert_eq!(d.added.iter().map(|h| h.ip.as_str()).collect::<Vec<_>>(), ["10.0.0.9"]);
        assert_eq!(d.gone.iter().map(|h| h.ip.as_str()).collect::<Vec<_>>(), ["10.0.0.4"]);
        let by_ip: HashMap<&str, &Change> = d.changed.iter().map(|c| (c.host.ip.as_str(), c)).collect();
        assert_eq!(by_ip.len(), 3);
        assert_eq!((by_ip["10.0.0.2"].opened.as_slice(), by_ip["10.0.0.2"].closed.as_slice()), (&[443][..], &[22][..]));
        assert_eq!(by_ip["10.0.0.30"].old_ip.as_deref(), Some("10.0.0.3"));
        assert_eq!(by_ip["10.0.0.5"].old_mac.as_deref(), Some("AA:00:00:00:00:05"));
    }

    #[test]
    fn round_trips_through_sqlite() {
        let mut conn = open(Path::new(":memory:")).unwrap();
        let first = scan(0, vec![host("10.0.0.1", "AA:00:00:00:00:01", &[80])]);
        let id1 = save(&mut conn, &first.summary, &first.hosts).unwrap();
        let second = scan(0, vec![]);
        let id2 = save(&mut conn, &second.summary, &second.hosts).unwrap();

        assert_eq!(list(&conn).unwrap().iter().map(|s| s.id).collect::<Vec<_>>(), [id2, id1]);
        let loaded = load(&conn, id1).unwrap();
        assert_eq!(loaded.hosts[0].ports, [80]);
        let s2 = load(&conn, id2).unwrap().summary;
        assert_eq!(baseline_for(&conn, &s2).unwrap(), Some(id1));

        delete(&conn, id1).unwrap();
        assert_eq!(list(&conn).unwrap().len(), 1);
        let orphans: i64 = conn.query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0)).unwrap();
        assert_eq!(orphans, 0);
    }
}
