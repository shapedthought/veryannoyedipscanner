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
        self.0
            .lock()
            .map_err(|e| format!("History database lock poisoned: {e}"))
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct ScanSummary {
    pub id: i64,
    pub started_at: i64,
    pub finished_at: i64,
    /// The targets as typed, e.g. "192.168.0.0/24, 10.0.1.5". Empty for scans
    /// saved before multi-target support.
    #[serde(default)]
    pub targets: String,
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
    // Added after the first release; older databases don't have it.
    let _ = conn.execute(
        "ALTER TABLE scans ADD COLUMN targets TEXT NOT NULL DEFAULT ''",
        [],
    );
    // Host rows started out addressed only by scan and IP; a device key makes
    // "show me this thing over time" a single query.
    let _ = conn.execute(
        "ALTER TABLE hosts ADD COLUMN key TEXT NOT NULL DEFAULT ''",
        [],
    );
    conn.execute_batch("CREATE INDEX IF NOT EXISTS hosts_by_key ON hosts (key)")?;
    backfill_keys(&conn)?;
    crate::devices::create_table(&conn)?;
    Ok(conn)
}

/// Fill in device keys for rows written before the column existed. One pass,
/// the first time a new build opens an old database.
fn backfill_keys(conn: &Connection) -> rusqlite::Result<()> {
    let rows: Vec<(i64, String, String)> = {
        let mut stmt = conn.prepare("SELECT scan_id, ip, data FROM hosts WHERE key = ''")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>();
        rows?
    };
    if rows.is_empty() {
        return Ok(());
    }
    let mut update = conn.prepare("UPDATE hosts SET key = ?1 WHERE scan_id = ?2 AND ip = ?3")?;
    for (scan_id, ip, data) in rows {
        let key = serde_json::from_str::<HostResult>(&data)
            .map(|host| crate::devices::key_for(&host))
            .unwrap_or_else(|_| format!("ip:{ip}"));
        update.execute(params![key, scan_id, ip])?;
    }
    Ok(())
}

/// Persist a finished scan. Only live hosts are stored; dead ones are implied
/// by the range.
pub fn save(
    conn: &mut Connection,
    summary: &ScanSummary,
    hosts: &[HostResult],
) -> rusqlite::Result<i64> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO scans (started_at, finished_at, range_start, range_end, ports, total, alive, targets)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            summary.started_at,
            summary.finished_at,
            summary.range_start,
            summary.range_end,
            serde_json::to_string(&summary.ports).unwrap(),
            summary.total,
            summary.alive,
            summary.targets,
        ],
    )?;
    let id = tx.last_insert_rowid();
    {
        let mut stmt =
            tx.prepare("INSERT INTO hosts (scan_id, ip, data, key) VALUES (?1, ?2, ?3, ?4)")?;
        for host in hosts.iter().filter(|h| h.alive) {
            let data = serde_json::to_string(host).unwrap();
            stmt.execute(params![id, host.ip, data, crate::devices::key_for(host)])?;
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
        targets: row.get(8)?,
    })
}

const SUMMARY_COLS: &str =
    "id, started_at, finished_at, range_start, range_end, ports, total, alive, targets";

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<ScanSummary>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SUMMARY_COLS} FROM scans ORDER BY id DESC"
    ))?;
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
    // Match on the written targets where we have them, so "the same scan"
    // means the same instruction rather than a coincidentally equal span.
    conn.query_row(
        "SELECT id FROM scans
         WHERE id < ?1
           AND CASE WHEN ?2 != '' AND targets != '' THEN targets = ?2
                    ELSE range_start = ?3 AND range_end = ?4 END
         ORDER BY id DESC LIMIT 1",
        params![scan.id, scan.targets, scan.range_start, scan.range_end],
        |row| row.get(0),
    )
    .optional()
}

/// One scan's worth of evidence about a device.
#[derive(Serialize, Clone, Debug)]
pub struct Sighting {
    pub scan_id: i64,
    pub at: i64,
    pub present: bool,
    /// Where it was that time, when it was there.
    pub ip: String,
    pub ports: Vec<u16>,
    pub alive_via: String,
}

#[derive(Serialize, Debug)]
pub struct DeviceHistory {
    pub key: String,
    /// Oldest first, covering only scans that looked where this device lives.
    pub sightings: Vec<Sighting>,
}

/// Every scan that covered this device's address, and whether it answered.
/// A scan of a different range isn't evidence of absence, so it's left out.
pub fn device_history(conn: &Connection, key: &str, ip: &str) -> rusqlite::Result<DeviceHistory> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {}, h.data FROM scans s
         LEFT JOIN hosts h ON h.scan_id = s.id AND h.key = ?1
         ORDER BY s.id",
        SUMMARY_COLS.replace("id,", "s.id,")
    ))?;
    let rows = stmt.query_map([key], |row| {
        let summary = summary_from_row(row)?;
        let data: Option<String> = row.get("data")?;
        Ok((summary, data))
    })?;

    let mut sightings = Vec::new();
    for row in rows {
        let (summary, data) = row?;
        let host = data.and_then(|d| serde_json::from_str::<HostResult>(&d).ok());
        // Absence only counts where the scan actually looked.
        let covered = host.is_some() || in_range(ip, &summary);
        if !covered {
            continue;
        }
        sightings.push(Sighting {
            scan_id: summary.id,
            at: summary.finished_at,
            present: host.is_some(),
            ip: host
                .as_ref()
                .map_or_else(|| ip.to_string(), |h| h.ip.clone()),
            ports: host.as_ref().map(|h| h.ports.clone()).unwrap_or_default(),
            alive_via: host.map(|h| h.alive_via).unwrap_or_default(),
        });
    }
    Ok(DeviceHistory {
        key: key.to_string(),
        sightings,
    })
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
    counts
        .into_iter()
        .filter(|(_, (n, _))| *n == 1)
        .map(|(m, (_, i))| (m, i))
        .collect()
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
    let old_by_ip: HashMap<&str, usize> = o
        .iter()
        .enumerate()
        .filter(|(i, _)| !old_used[*i])
        .map(|(i, h)| (h.ip.as_str(), i))
        .collect();
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
    let scanned: BTreeSet<u16> = old
        .summary
        .ports
        .iter()
        .copied()
        .filter(|p| new.summary.ports.contains(p))
        .collect();
    let mut changed: Vec<Change> = pairs
        .into_iter()
        .filter_map(|(oi, ni)| {
            let (a, b) = (&o[oi], &n[ni]);
            let pa: BTreeSet<u16> = a
                .ports
                .iter()
                .copied()
                .filter(|p| scanned.contains(p))
                .collect();
            let pb: BTreeSet<u16> = b
                .ports
                .iter()
                .copied()
                .filter(|p| scanned.contains(p))
                .collect();
            let change = Change {
                host: b.clone(),
                old_ip: (a.ip != b.ip).then(|| a.ip.clone()),
                old_mac: (!a.mac.is_empty() && !b.mac.is_empty() && a.mac != b.mac)
                    .then(|| a.mac.clone()),
                // Reverse DNS is flaky, so only report a rename, not a blank.
                old_hostname: (!a.hostname.is_empty()
                    && !b.hostname.is_empty()
                    && a.hostname != b.hostname)
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
    let added = n
        .iter()
        .enumerate()
        .filter(|(i, h)| !new_used[*i] && in_range(&h.ip, &old.summary))
        .map(|(_, h)| h.clone())
        .collect();
    let gone = o
        .iter()
        .enumerate()
        .filter(|(i, h)| !old_used[*i] && in_range(&h.ip, &new.summary))
        .map(|(_, h)| h.clone())
        .collect();

    Diff {
        old: old.summary.clone(),
        new: new.summary.clone(),
        added,
        gone,
        changed,
    }
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
                targets: "10.0.0.1-254".into(),
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
        let old = scan(
            1,
            vec![
                host("10.0.0.1", "AA:00:00:00:00:01", &[80]), // router, unchanged
                host("10.0.0.2", "AA:00:00:00:00:02", &[22]), // gets 443 opened, 22 closed
                host("10.0.0.3", "AA:00:00:00:00:03", &[]),   // moves to .30
                host("10.0.0.4", "AA:00:00:00:00:04", &[]),   // disappears
                host("10.0.0.5", "AA:00:00:00:00:05", &[]),   // IP taken over by new MAC
            ],
        );
        let new = scan(
            2,
            vec![
                host("10.0.0.1", "AA:00:00:00:00:01", &[80, 8080]), // 8080 wasn't scanned before
                host("10.0.0.2", "AA:00:00:00:00:02", &[443]),
                host("10.0.0.30", "AA:00:00:00:00:03", &[]),
                host("10.0.0.5", "BB:00:00:00:00:05", &[]),
                host("10.0.0.9", "", &[22]), // brand new
            ],
        );
        let d = diff(&old, &new);

        assert_eq!(
            d.added.iter().map(|h| h.ip.as_str()).collect::<Vec<_>>(),
            ["10.0.0.9"]
        );
        assert_eq!(
            d.gone.iter().map(|h| h.ip.as_str()).collect::<Vec<_>>(),
            ["10.0.0.4"]
        );
        let by_ip: HashMap<&str, &Change> =
            d.changed.iter().map(|c| (c.host.ip.as_str(), c)).collect();
        assert_eq!(by_ip.len(), 3);
        assert_eq!(
            (
                by_ip["10.0.0.2"].opened.as_slice(),
                by_ip["10.0.0.2"].closed.as_slice()
            ),
            (&[443][..], &[22][..])
        );
        assert_eq!(by_ip["10.0.0.30"].old_ip.as_deref(), Some("10.0.0.3"));
        assert_eq!(
            by_ip["10.0.0.5"].old_mac.as_deref(),
            Some("AA:00:00:00:00:05")
        );
    }

    /// A database written before multi-target support must keep working.
    #[test]
    fn migrates_a_database_without_targets() {
        let dir = std::env::temp_dir().join(format!("vais-migration-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.sqlite");
        let _ = std::fs::remove_file(&path);

        // The original schema, as shipped in v0.1.0.
        let old = Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE scans (
                 id INTEGER PRIMARY KEY, started_at INTEGER NOT NULL,
                 finished_at INTEGER NOT NULL, range_start TEXT NOT NULL,
                 range_end TEXT NOT NULL, ports TEXT NOT NULL,
                 total INTEGER NOT NULL, alive INTEGER NOT NULL);
             INSERT INTO scans VALUES (1, 10, 20, '10.0.0.1', '10.0.0.254', '[22]', 254, 3);
             CREATE TABLE hosts (scan_id INTEGER NOT NULL, ip TEXT NOT NULL, data TEXT NOT NULL,
                 PRIMARY KEY (scan_id, ip));",
        )
        .unwrap();
        drop(old);

        let conn = open(&path).unwrap();
        let scans = list(&conn).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].targets, "", "old rows have no written targets");

        // And an old scan is still a valid baseline for a new one of the same span.
        let mut conn = conn;
        let next = ScanSummary {
            id: 0,
            targets: "10.0.0.1-254".into(),
            range_start: "10.0.0.1".into(),
            range_end: "10.0.0.254".into(),
            ports: vec![22],
            started_at: 30,
            finished_at: 40,
            total: 254,
            alive: 3,
        };
        let id = save(&mut conn, &next, &[]).unwrap();
        let saved = load(&conn, id).unwrap().summary;
        assert_eq!(baseline_for(&conn, &saved).unwrap(), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timelines_count_only_scans_that_looked() {
        let mut conn = open(Path::new(":memory:")).unwrap();
        let mac = "AA:00:00:00:00:01";
        let here = |ip: &str| HostResult {
            ip: ip.into(),
            alive: true,
            mac: mac.into(),
            ports: vec![22],
            ..Default::default()
        };

        // Two scans of this range: present, then absent. Then a scan of a
        // different range entirely, which says nothing either way.
        let mut spec = scan(0, vec![here("10.0.0.5")]);
        save(&mut conn, &spec.summary, &spec.hosts).unwrap();
        spec.hosts.clear();
        save(&mut conn, &spec.summary, &spec.hosts).unwrap();
        let elsewhere = ScanSummary {
            targets: "192.168.5.0/24".into(),
            range_start: "192.168.5.1".into(),
            range_end: "192.168.5.254".into(),
            ..spec.summary.clone()
        };
        save(&mut conn, &elsewhere, &[]).unwrap();

        let timeline = device_history(&conn, mac, "10.0.0.5").unwrap();
        assert_eq!(
            timeline
                .sightings
                .iter()
                .map(|s| s.present)
                .collect::<Vec<_>>(),
            [true, false],
            "the scan of another range is not evidence of absence"
        );
        assert_eq!(timeline.sightings[0].ports, [22]);
        assert_eq!(timeline.sightings[0].ip, "10.0.0.5");
    }

    #[test]
    fn timelines_follow_a_device_that_moved() {
        let mut conn = open(Path::new(":memory:")).unwrap();
        let mac = "AA:00:00:00:00:02";
        let at = |ip: &str| HostResult {
            ip: ip.into(),
            alive: true,
            mac: mac.into(),
            ..Default::default()
        };
        let mut spec = scan(0, vec![at("10.0.0.5")]);
        save(&mut conn, &spec.summary, &spec.hosts).unwrap();
        spec.hosts = vec![at("10.0.0.99")];
        save(&mut conn, &spec.summary, &spec.hosts).unwrap();

        let timeline = device_history(&conn, mac, "10.0.0.99").unwrap();
        assert_eq!(
            timeline
                .sightings
                .iter()
                .map(|s| s.ip.as_str())
                .collect::<Vec<_>>(),
            ["10.0.0.5", "10.0.0.99"],
            "one device, two addresses"
        );
    }

    #[test]
    fn baselines_match_on_what_was_asked_for() {
        let mut conn = open(Path::new(":memory:")).unwrap();
        let spec = |targets: &str, start: &str, end: &str| ScanSummary {
            id: 0,
            targets: targets.into(),
            range_start: start.into(),
            range_end: end.into(),
            ports: vec![22],
            started_at: 0,
            finished_at: 0,
            total: 1,
            alive: 0,
        };
        // Same written targets, different resulting span (a host at the end
        // simply wasn't up the first time).
        let first = save(
            &mut conn,
            &spec("10.0.0.0/24, 10.0.1.5", "10.0.0.1", "10.0.0.9"),
            &[],
        )
        .unwrap();
        let second = save(
            &mut conn,
            &spec("10.0.0.0/24, 10.0.1.5", "10.0.0.1", "10.0.1.5"),
            &[],
        )
        .unwrap();
        let loaded = load(&conn, second).unwrap().summary;
        assert_eq!(baseline_for(&conn, &loaded).unwrap(), Some(first));

        // A different instruction is not a baseline, even overlapping.
        let other = save(&mut conn, &spec("10.0.0.0/25", "10.0.0.1", "10.0.0.9"), &[]).unwrap();
        let loaded = load(&conn, other).unwrap().summary;
        assert_eq!(baseline_for(&conn, &loaded).unwrap(), None);
    }

    #[test]
    fn round_trips_through_sqlite() {
        let mut conn = open(Path::new(":memory:")).unwrap();
        let first = scan(0, vec![host("10.0.0.1", "AA:00:00:00:00:01", &[80])]);
        let id1 = save(&mut conn, &first.summary, &first.hosts).unwrap();
        let second = scan(0, vec![]);
        let id2 = save(&mut conn, &second.summary, &second.hosts).unwrap();

        assert_eq!(
            list(&conn)
                .unwrap()
                .iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
            [id2, id1]
        );
        let loaded = load(&conn, id1).unwrap();
        assert_eq!(loaded.hosts[0].ports, [80]);
        let s2 = load(&conn, id2).unwrap().summary;
        assert_eq!(baseline_for(&conn, &s2).unwrap(), Some(id1));

        delete(&conn, id1).unwrap();
        assert_eq!(list(&conn).unwrap().len(), 1);
        let orphans: i64 = conn
            .query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(orphans, 0);
    }
}
