//! The handful of things you actually care about staying up.
//!
//! A full scan is too slow and too noisy to answer "is the NAS still there?".
//! A watch is one host, or one host and port, checked often, with enough
//! history kept to tell a blip from an outage.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

/// Checks older than this are pruned: enough to see today's flapping.
const KEEP_FOR_MS: i64 = 24 * 3600 * 1000;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Watch {
    pub id: i64,
    pub profile_id: Option<i64>,
    /// The device this belongs to, so it survives a change of address.
    pub key: String,
    pub ip: String,
    /// None means "is the host up at all"; a port means that service.
    pub port: Option<u16>,
    pub label: String,
    /// "up", "down", or "" before the first check.
    pub state: String,
    pub changed_at: i64,
    pub checked_at: i64,
}

/// What to say when a watch changes state.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Transition {
    pub watch: Watch,
    pub up: bool,
    /// How long it spent in the previous state, in milliseconds.
    pub after_ms: i64,
}

pub fn create_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS watches (
             id         INTEGER PRIMARY KEY,
             profile_id INTEGER,
             key        TEXT NOT NULL,
             ip         TEXT NOT NULL,
             port       INTEGER,
             label      TEXT NOT NULL DEFAULT '',
             state      TEXT NOT NULL DEFAULT '',
             changed_at INTEGER NOT NULL DEFAULT 0,
             checked_at INTEGER NOT NULL DEFAULT 0
         );
         -- NULLs are distinct in a UNIQUE constraint, so a host-level watch
         -- (port NULL) would never collide with itself. Coalesce instead.
         CREATE UNIQUE INDEX IF NOT EXISTS watches_unique
             ON watches (COALESCE(profile_id, -1), key, COALESCE(port, -1));
         CREATE TABLE IF NOT EXISTS watch_checks (
             watch_id INTEGER NOT NULL REFERENCES watches(id) ON DELETE CASCADE,
             at       INTEGER NOT NULL,
             up       INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS watch_checks_by_watch ON watch_checks (watch_id, at);",
    )
}

fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Watch> {
    Ok(Watch {
        id: row.get(0)?,
        profile_id: row.get(1)?,
        key: row.get(2)?,
        ip: row.get(3)?,
        port: row.get::<_, Option<i64>>(4)?.map(|p| p as u16),
        label: row.get(5)?,
        state: row.get(6)?,
        changed_at: row.get(7)?,
        checked_at: row.get(8)?,
    })
}

const COLS: &str = "id, profile_id, key, ip, port, label, state, changed_at, checked_at";

pub fn list(conn: &Connection, profile_id: Option<i64>) -> rusqlite::Result<Vec<Watch>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLS} FROM watches WHERE profile_id IS ?1 ORDER BY ip, port"
    ))?;
    let watches = stmt.query_map([profile_id], from_row)?.collect();
    watches
}

pub fn add(
    conn: &Connection,
    profile_id: Option<i64>,
    key: &str,
    ip: &str,
    port: Option<u16>,
    label: &str,
) -> rusqlite::Result<Watch> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM watches WHERE profile_id IS ?1 AND key = ?2 AND port IS ?3",
            params![profile_id, key, port],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(id) => conn.execute(
            "UPDATE watches SET label = ?2 WHERE id = ?1",
            params![id, label],
        )?,
        None => conn.execute(
            "INSERT INTO watches (profile_id, key, ip, port, label) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![profile_id, key, ip, port, label],
        )?,
    };
    // One device, one address: every watch on it follows the device.
    follow(conn, profile_id, key, ip)?;
    conn.query_row(
        &format!("SELECT {COLS} FROM watches WHERE profile_id IS ?1 AND key = ?2 AND port IS ?3"),
        params![profile_id, key, port],
        from_row,
    )
}

/// Point every watch on this device at the address it answers on now.
pub fn follow(
    conn: &Connection,
    profile_id: Option<i64>,
    key: &str,
    ip: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE watches SET ip = ?3 WHERE profile_id IS ?1 AND key = ?2 AND ip != ?3",
        params![profile_id, key, ip],
    )?;
    Ok(())
}

pub fn remove(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM watch_checks WHERE watch_id = ?1", [id])?;
    conn.execute("DELETE FROM watches WHERE id = ?1", [id])?;
    Ok(())
}

/// Record a check. Returns a transition only when the state actually changed,
/// so a watch that stays up says nothing.
pub fn record(
    conn: &Connection,
    watch: &Watch,
    up: bool,
    now: i64,
) -> rusqlite::Result<Option<Transition>> {
    let state = if up { "up" } else { "down" };
    let changed = watch.state != state;
    conn.execute(
        "UPDATE watches SET state = ?2, checked_at = ?3, changed_at = CASE WHEN ?4 THEN ?3 ELSE changed_at END
         WHERE id = ?1",
        params![watch.id, state, now, changed],
    )?;
    conn.execute(
        "INSERT INTO watch_checks (watch_id, at, up) VALUES (?1, ?2, ?3)",
        params![watch.id, now, up],
    )?;
    conn.execute(
        "DELETE FROM watch_checks WHERE watch_id = ?1 AND at < ?2",
        params![watch.id, now - KEEP_FOR_MS],
    )?;

    // The first check establishes a state rather than announcing a change.
    if !changed || watch.state.is_empty() {
        return Ok(None);
    }
    let updated = conn
        .query_row(
            &format!("SELECT {COLS} FROM watches WHERE id = ?1"),
            [watch.id],
            from_row,
        )
        .optional()?;
    Ok(updated.map(|watch| Transition {
        up,
        after_ms: now - watch.changed_at.max(0),
        watch,
    }))
}

/// Recent checks, oldest first, for drawing what today looked like.
pub fn checks(conn: &Connection, watch_id: i64) -> rusqlite::Result<Vec<(i64, bool)>> {
    let mut stmt = conn.prepare(
        "SELECT at, up FROM watch_checks WHERE watch_id = ?1 ORDER BY at DESC LIMIT 200",
    )?;
    let mut rows: Vec<(i64, bool)> = stmt
        .query_map([watch_id], |row| {
            Ok((row.get(0)?, row.get::<_, i64>(1)? != 0))
        })?
        .collect::<rusqlite::Result<_>>()?;
    rows.reverse();
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history;
    use std::path::Path;

    fn db() -> Connection {
        history::open(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn a_host_and_its_ports_are_separate_watches() {
        let conn = db();
        let mac = "AA:BB:CC:00:00:01";
        add(&conn, Some(1), mac, "10.0.0.5", None, "NAS").unwrap();
        add(&conn, Some(1), mac, "10.0.0.5", Some(5001), "NAS web").unwrap();
        // The same one again updates rather than duplicating.
        add(&conn, Some(1), mac, "10.0.0.9", None, "NAS").unwrap();

        let watches = list(&conn, Some(1)).unwrap();
        assert_eq!(watches.len(), 2);
        assert_eq!(watches[0].port, None, "the host itself");
        assert_eq!(watches[1].port, Some(5001));
        // The device moved, so both of its watches moved with it.
        assert!(watches.iter().all(|w| w.ip == "10.0.0.9"));
        assert!(
            list(&conn, Some(2)).unwrap().is_empty(),
            "watches belong to a network"
        );
    }

    #[test]
    fn only_changes_are_announced() {
        let conn = db();
        let watch = add(&conn, None, "AA:BB", "10.0.0.5", None, "NAS").unwrap();
        assert_eq!(watch.state, "");

        // First check establishes the state; nothing to announce yet.
        assert_eq!(record(&conn, &watch, true, 1_000).unwrap(), None);
        let watch = list(&conn, None).unwrap().remove(0);
        assert_eq!(watch.state, "up");

        // Still up: silence.
        assert_eq!(record(&conn, &watch, true, 2_000).unwrap(), None);
        let watch = list(&conn, None).unwrap().remove(0);

        // Gone: announced, with how long it had been up.
        let transition = record(&conn, &watch, false, 61_000).unwrap().unwrap();
        assert!(!transition.up);
        assert_eq!(
            transition.after_ms, 0,
            "it changed state at this very check"
        );
        let watch = list(&conn, None).unwrap().remove(0);
        assert_eq!(watch.state, "down");
        assert_eq!(watch.changed_at, 61_000);

        // Back again.
        let back = record(&conn, &watch, true, 121_000).unwrap().unwrap();
        assert!(back.up);
    }

    #[test]
    fn checks_are_kept_for_a_day_and_no_longer() {
        let conn = db();
        let watch = add(&conn, None, "AA:BB", "10.0.0.5", None, "").unwrap();
        let day = 24 * 3600 * 1000;
        record(&conn, &watch, true, 1_000).unwrap();
        let watch = list(&conn, None).unwrap().remove(0);
        record(&conn, &watch, true, 1_000 + day / 2).unwrap();
        assert_eq!(checks(&conn, watch.id).unwrap().len(), 2);

        // A check a day later prunes the oldest.
        let watch = list(&conn, None).unwrap().remove(0);
        record(&conn, &watch, true, 2_000 + day).unwrap();
        let kept = checks(&conn, watch.id).unwrap();
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].0, 1_000 + day / 2, "oldest to newest");
    }

    #[test]
    fn removing_a_watch_takes_its_history() {
        let conn = db();
        let watch = add(&conn, None, "AA:BB", "10.0.0.5", None, "").unwrap();
        record(&conn, &watch, true, 1_000).unwrap();
        remove(&conn, watch.id).unwrap();
        assert!(list(&conn, None).unwrap().is_empty());
        assert!(checks(&conn, watch.id).unwrap().is_empty());
    }
}
