//! The devices you know about: names you gave them, notes, and whether
//! you've said they belong here.
//!
//! Scan rows describe an address at a moment. A device outlives both: it keeps
//! its name when its IP changes, and stays approved between scans. Identity is
//! the MAC where we have one, since that survives DHCP.

use crate::scanner::HostResult;
use rusqlite::{params, Connection};
use serde::Serialize;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Device {
    pub key: String,
    /// What you call it, as opposed to what it calls itself.
    pub label: String,
    pub note: String,
    pub approved: bool,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// How a host maps to a device. Without a MAC (anything off the local subnet)
/// the address is the best identity available.
pub fn key_for(host: &HostResult) -> String {
    if host.mac.is_empty() {
        format!("ip:{}", host.ip)
    } else {
        host.mac.clone()
    }
}

pub fn create_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS devices (
             key        TEXT PRIMARY KEY,
             label      TEXT NOT NULL DEFAULT '',
             note       TEXT NOT NULL DEFAULT '',
             approved   INTEGER NOT NULL DEFAULT 0,
             first_seen INTEGER NOT NULL,
             last_seen  INTEGER NOT NULL
         );",
    )
}

fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Device> {
    Ok(Device {
        key: row.get(0)?,
        label: row.get(1)?,
        note: row.get(2)?,
        approved: row.get::<_, i64>(3)? != 0,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
    })
}

const COLS: &str = "key, label, note, approved, first_seen, last_seen";

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<Device>> {
    let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM devices ORDER BY key"))?;
    let devices = stmt.query_map([], from_row)?.collect();
    devices
}

pub fn set_label(
    conn: &Connection,
    key: &str,
    label: &str,
    note: &str,
    now: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO devices (key, label, note, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(key) DO UPDATE SET label = ?2, note = ?3",
        params![key, label, note, now],
    )?;
    Ok(())
}

pub fn set_approved(
    conn: &Connection,
    key: &str,
    approved: bool,
    now: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO devices (key, approved, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(key) DO UPDATE SET approved = ?2",
        params![key, approved, now],
    )?;
    Ok(())
}

pub fn forget(conn: &Connection, key: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM devices WHERE key = ?1", [key])?;
    Ok(())
}

/// Record that these hosts were seen now. Devices are created on first
/// sighting so that "first seen" means something later.
pub fn record_sightings(
    conn: &mut Connection,
    hosts: &[HostResult],
    now: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO devices (key, first_seen, last_seen) VALUES (?1, ?2, ?2)
             ON CONFLICT(key) DO UPDATE SET last_seen = ?2",
        )?;
        for host in hosts.iter().filter(|h| h.alive) {
            stmt.execute(params![key_for(host), now])?;
        }
    }
    tx.commit()
}

/// Whether the user has started approving devices *on this network*. Until
/// they have, flagging every device as unknown would be noise - and arriving
/// somewhere new shouldn't light up every row just because you've curated a
/// different network.
pub fn any_approved(conn: &Connection, profile_id: Option<i64>) -> rusqlite::Result<bool> {
    let Some(profile_id) = profile_id else {
        return conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE approved != 0)",
            [],
            |row| Ok(row.get::<_, i64>(0)? != 0),
        );
    };
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM devices d
             JOIN hosts h ON h.key = d.key
             JOIN scans s ON s.id = h.scan_id
             WHERE d.approved != 0 AND s.profile_id = ?1
         )",
        [profile_id],
        |row| Ok(row.get::<_, i64>(0)? != 0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    fn host(ip: &str, mac: &str) -> HostResult {
        HostResult {
            ip: ip.into(),
            mac: mac.into(),
            alive: true,
            ..Default::default()
        }
    }

    /// Devices by key, for asserting about one in particular.
    fn by_key(conn: &Connection) -> HashMap<String, Device> {
        list(conn)
            .unwrap()
            .into_iter()
            .map(|device| (device.key.clone(), device))
            .collect()
    }

    fn db() -> Connection {
        let conn = Connection::open(Path::new(":memory:")).unwrap();
        create_table(&conn).unwrap();
        conn
    }

    /// Approvals are per network: curating home shouldn't flag every device
    /// at someone else's house, or leave it silently unflagged either.
    #[test]
    fn approval_is_judged_per_network() {
        let mut conn = crate::history::open(Path::new(":memory:")).unwrap();
        let home = crate::profiles::create(&conn, "Home", "gw:AA", "", "", 1).unwrap();
        let away = crate::profiles::create(&conn, "Away", "gw:BB", "", "", 1).unwrap();

        let laptop = host("10.0.0.5", "AA:00:00:00:00:01");
        let scan = crate::history::ScanSummary {
            id: 0,
            profile_id: Some(home.id),
            targets: "10.0.0.0/24".into(),
            range_start: "10.0.0.1".into(),
            range_end: "10.0.0.254".into(),
            ports: vec![22],
            started_at: 0,
            finished_at: 0,
            total: 254,
            alive: 1,
        };
        crate::history::save(&mut conn, &scan, std::slice::from_ref(&laptop)).unwrap();
        set_approved(&conn, &key_for(&laptop), true, 10).unwrap();

        assert!(any_approved(&conn, Some(home.id)).unwrap());
        assert!(
            !any_approved(&conn, Some(away.id)).unwrap(),
            "nothing has been approved on this network yet"
        );
    }

    #[test]
    fn identity_prefers_mac_and_falls_back_to_ip() {
        assert_eq!(
            key_for(&host("10.0.0.5", "AA:BB:CC:DD:EE:FF")),
            "AA:BB:CC:DD:EE:FF"
        );
        assert_eq!(key_for(&host("10.0.0.5", "")), "ip:10.0.0.5");
    }

    #[test]
    fn labels_and_approval_survive_a_change_of_address() {
        let mut conn = db();
        let mac = "AA:BB:CC:DD:EE:FF";
        set_label(&conn, mac, "Dad's iPad", "the loud one", 100).unwrap();
        set_approved(&conn, mac, true, 100).unwrap();

        // Same device, new address.
        record_sightings(&mut conn, &[host("10.0.0.9", mac)], 500).unwrap();
        let device = &by_key(&conn)[mac];
        assert_eq!(
            (device.label.as_str(), device.approved),
            ("Dad's iPad", true)
        );
        assert_eq!((device.first_seen, device.last_seen), (100, 500));
    }

    #[test]
    fn sightings_create_devices_and_track_time() {
        let mut conn = db();
        assert!(!any_approved(&conn, None).unwrap());

        let hosts = [host("10.0.0.1", "AA:00:00:00:00:01"), host("10.0.0.2", "")];
        record_sightings(&mut conn, &hosts, 1_000).unwrap();
        record_sightings(&mut conn, &hosts[..1], 2_000).unwrap();

        let devices = by_key(&conn);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices["AA:00:00:00:00:01"].last_seen, 2_000);
        assert_eq!(
            devices["ip:10.0.0.2"].last_seen, 1_000,
            "not seen in the second scan"
        );
        assert_eq!(devices["AA:00:00:00:00:01"].first_seen, 1_000);

        set_approved(&conn, "AA:00:00:00:00:01", true, 3_000).unwrap();
        assert!(any_approved(&conn, None).unwrap());
        // Approving mustn't disturb when it was first seen.
        assert_eq!(by_key(&conn)["AA:00:00:00:00:01"].first_seen, 1_000);

        forget(&conn, "AA:00:00:00:00:01").unwrap();
        assert_eq!(list(&conn).unwrap().len(), 1);
        assert!(!any_approved(&conn, None).unwrap());
    }

    #[test]
    fn dead_hosts_are_not_sightings() {
        let mut conn = db();
        let mut dead = host("10.0.0.3", "AA:00:00:00:00:03");
        dead.alive = false;
        record_sightings(&mut conn, &[dead], 100).unwrap();
        assert!(list(&conn).unwrap().is_empty());
    }
}
