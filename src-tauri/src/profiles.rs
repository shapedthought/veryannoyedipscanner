//! Networks you've been on, and which scans belong to which.
//!
//! Without this, history is keyed by address range — so a scan at someone
//! else's house is compared against your own, because both are 192.168.0.x.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Profile {
    pub id: i64,
    pub name: String,
    /// The network fingerprint this profile was created from.
    pub fingerprint: String,
    /// What to scan here, remembered so arriving somewhere else doesn't scan
    /// the last place's range.
    pub targets: String,
    pub created_at: i64,
    pub last_seen_at: i64,
}

pub fn create_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS profiles (
             id           INTEGER PRIMARY KEY,
             name         TEXT NOT NULL,
             fingerprint  TEXT NOT NULL UNIQUE,
             targets      TEXT NOT NULL DEFAULT '',
             created_at   INTEGER NOT NULL,
             last_seen_at INTEGER NOT NULL
         );",
    )?;
    // Scans predate profiles; unassigned ones stay that way until adopted.
    let _ = conn.execute("ALTER TABLE scans ADD COLUMN profile_id INTEGER", []);
    Ok(())
}

fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Profile> {
    Ok(Profile {
        id: row.get(0)?,
        name: row.get(1)?,
        fingerprint: row.get(2)?,
        targets: row.get(3)?,
        created_at: row.get(4)?,
        last_seen_at: row.get(5)?,
    })
}

const COLS: &str = "id, name, fingerprint, targets, created_at, last_seen_at";

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<Profile>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLS} FROM profiles ORDER BY last_seen_at DESC"
    ))?;
    let profiles = stmt.query_map([], from_row)?.collect();
    profiles
}

pub fn by_fingerprint(conn: &Connection, fingerprint: &str) -> rusqlite::Result<Option<Profile>> {
    conn.query_row(
        &format!("SELECT {COLS} FROM profiles WHERE fingerprint = ?1"),
        [fingerprint],
        from_row,
    )
    .optional()
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<Profile>> {
    conn.query_row(
        &format!("SELECT {COLS} FROM profiles WHERE id = ?1"),
        [id],
        from_row,
    )
    .optional()
}

/// Create a profile, and adopt any scans that were saved before profiles
/// existed and cover the same subnet - almost certainly this network.
pub fn create(
    conn: &Connection,
    name: &str,
    fingerprint: &str,
    targets: &str,
    subnet_prefix: &str,
    now: i64,
) -> rusqlite::Result<Profile> {
    conn.execute(
        "INSERT INTO profiles (name, fingerprint, targets, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(fingerprint) DO UPDATE SET name = ?1, targets = ?3, last_seen_at = ?4",
        params![name.trim(), fingerprint, targets, now],
    )?;
    let profile = by_fingerprint(conn, fingerprint)?.expect("just inserted");
    if !subnet_prefix.is_empty() {
        conn.execute(
            "UPDATE scans SET profile_id = ?1
             WHERE profile_id IS NULL AND range_start LIKE ?2",
            params![profile.id, format!("{subnet_prefix}%")],
        )?;
    }
    Ok(profile)
}

pub fn rename(conn: &Connection, id: i64, name: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE profiles SET name = ?2 WHERE id = ?1",
        params![id, name.trim()],
    )?;
    Ok(())
}

pub fn remember_targets(conn: &Connection, id: i64, targets: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE profiles SET targets = ?2 WHERE id = ?1",
        params![id, targets],
    )?;
    Ok(())
}

pub fn touch(conn: &Connection, id: i64, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE profiles SET last_seen_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    Ok(())
}

/// Forget a profile. Its scans stay, unassigned, rather than vanishing.
pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE scans SET profile_id = NULL WHERE profile_id = ?1",
        [id],
    )?;
    conn.execute("DELETE FROM profiles WHERE id = ?1", [id])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history;
    use std::path::Path;

    fn db() -> Connection {
        history::open(Path::new(":memory:")).unwrap()
    }

    fn scan_of(range_start: &str) -> history::ScanSummary {
        history::ScanSummary {
            id: 0,
            profile_id: None,
            suspect: false,
            targets: format!("{range_start}/24"),
            range_start: range_start.into(),
            range_end: range_start.into(),
            ports: vec![22],
            started_at: 0,
            finished_at: 0,
            total: 1,
            alive: 0,
        }
    }

    #[test]
    fn profiles_are_found_by_fingerprint() {
        let conn = db();
        let made = create(
            &conn,
            "Home",
            "gw:AA:BB",
            "192.168.0.0/24",
            "192.168.0.",
            100,
        )
        .unwrap();
        assert_eq!(
            by_fingerprint(&conn, "gw:AA:BB").unwrap(),
            Some(made.clone())
        );
        assert_eq!(by_fingerprint(&conn, "gw:00:00").unwrap(), None);
        assert_eq!(get(&conn, made.id).unwrap().unwrap().name, "Home");
    }

    #[test]
    fn creating_a_profile_adopts_matching_legacy_scans() {
        let mut conn = db();
        // Two old scans of this subnet, one of somewhere else entirely.
        history::save(&mut conn, &scan_of("192.168.0.1"), &[]).unwrap();
        history::save(&mut conn, &scan_of("192.168.0.1"), &[]).unwrap();
        let elsewhere = history::save(&mut conn, &scan_of("10.20.30.1"), &[]).unwrap();

        let home = create(
            &conn,
            "Home",
            "gw:AA:BB",
            "192.168.0.0/24",
            "192.168.0.",
            100,
        )
        .unwrap();
        let adopted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scans WHERE profile_id = ?1",
                [home.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(adopted, 2);
        let orphan: Option<i64> = conn
            .query_row(
                "SELECT profile_id FROM scans WHERE id = ?1",
                [elsewhere],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphan, None, "another subnet is not this network");
    }

    #[test]
    fn deleting_a_profile_keeps_its_scans() {
        let mut conn = db();
        let profile = create(&conn, "Away", "gw:CC:DD", "10.0.0.0/24", "10.0.0.", 1).unwrap();
        history::save(&mut conn, &scan_of("10.0.0.1"), &[]).unwrap();
        conn.execute("UPDATE scans SET profile_id = ?1", [profile.id])
            .unwrap();

        delete(&conn, profile.id).unwrap();
        assert!(list(&conn).unwrap().is_empty());
        let scans: i64 = conn
            .query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
            .unwrap();
        assert_eq!(scans, 1, "history survives forgetting the network");
    }

    #[test]
    fn revisiting_updates_rather_than_duplicates() {
        let conn = db();
        let first = create(&conn, "Home", "gw:AA:BB", "192.168.0.0/24", "", 100).unwrap();
        let again = create(&conn, "Home again", "gw:AA:BB", "192.168.1.0/24", "", 500).unwrap();
        assert_eq!(first.id, again.id);
        assert_eq!(again.targets, "192.168.1.0/24");
        assert_eq!(list(&conn).unwrap().len(), 1);
    }
}
