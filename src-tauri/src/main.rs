#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod arp;
mod fdlimit;
mod history;
mod icmp;
mod probe;
mod scanner;
mod vendor;

use history::{Db, Diff, SavedScan, ScanSummary};
use scanner::{Cancel, HostResult, Options, Range};
use serde::Serialize;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Default)]
struct ScanState {
    generation: Arc<AtomicU64>,
}

#[derive(Serialize, Clone)]
struct RowEvent {
    generation: u64,
    host: HostResult,
}

#[derive(Serialize, Clone)]
struct DoneEvent {
    generation: u64,
    cancelled: bool,
    /// Id of the saved scan (None if cancelled or saving failed).
    scan_id: Option<i64>,
    /// Changes since the previous scan of the same range, if there was one.
    diff: Option<Diff>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ScanStarted {
    generation: u64,
    total: usize,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn db_err(e: rusqlite::Error) -> String {
    format!("History database is being difficult: {e}")
}

#[tauri::command]
fn local_range() -> Range {
    scanner::local_range()
}

#[tauri::command]
fn cidr_range(cidr: String) -> Result<Range, String> {
    scanner::cidr_range(&cidr)
}

/// Kick off a scan in the background; results stream back as `scan-row`
/// events and a final `scan-done` carrying the saved id and any diff.
#[tauri::command]
fn start_scan(
    app: AppHandle,
    state: State<'_, ScanState>,
    start: String,
    end: String,
    ports: String,
    threads: usize,
    options: Options,
) -> Result<ScanStarted, String> {
    let ips = scanner::ip_range(&start, &end)?;
    let ports = Arc::new(scanner::parse_ports(&ports)?);
    let options = options.sanitised();
    let threads = threads.clamp(1, 1024);

    let generation = state.generation.fetch_add(1, Ordering::SeqCst) + 1;
    let cancel = Cancel {
        current: state.generation.clone(),
        generation,
    };
    let total = ips.len();
    let range_start = ips.first().map(Ipv4Addr::to_string).unwrap_or_default();
    let range_end = ips.last().map(Ipv4Addr::to_string).unwrap_or_default();
    let started_at = now_ms();

    tauri::async_runtime::spawn(async move {
        let permits = Arc::new(Semaphore::new(threads));
        let mut tasks = JoinSet::new();
        let mut results = Vec::new();
        for ip in ips {
            let permit = permits
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore open");
            if cancel.is_cancelled() {
                break;
            }
            let (app, ports, cancel) = (app.clone(), ports.clone(), cancel.clone());
            tasks.spawn(async move {
                let host = scanner::scan_host(ip, &ports, &options, &cancel).await;
                drop(permit);
                if !cancel.is_cancelled() {
                    let _ = app.emit(
                        "scan-row",
                        RowEvent {
                            generation,
                            host: host.clone(),
                        },
                    );
                }
                host
            });
            while let Some(done) = tasks.try_join_next() {
                results.extend(done.ok());
            }
        }
        while let Some(done) = tasks.join_next().await {
            results.extend(done.ok());
        }

        let cancelled = cancel.is_cancelled();
        let mut event = DoneEvent {
            generation,
            cancelled,
            scan_id: None,
            diff: None,
            error: None,
        };
        // A partial scan would make everything it didn't reach look "gone",
        // so only complete scans go into history.
        if !cancelled {
            let summary = ScanSummary {
                id: 0,
                started_at,
                finished_at: now_ms(),
                range_start,
                range_end,
                ports: ports.to_vec(),
                total: total as i64,
                alive: results.iter().filter(|h| h.alive).count() as i64,
            };
            match save_and_diff(&app, summary, &results) {
                Ok((id, diff)) => {
                    event.scan_id = Some(id);
                    event.diff = diff;
                }
                Err(e) => event.error = Some(e),
            }
        }
        let _ = app.emit("scan-done", event);
    });

    Ok(ScanStarted { generation, total })
}

fn save_and_diff(
    app: &AppHandle,
    mut summary: ScanSummary,
    hosts: &[HostResult],
) -> Result<(i64, Option<Diff>), String> {
    let db = app.state::<Db>();
    let mut conn = db.conn()?;
    let id = history::save(&mut conn, &summary, hosts).map_err(db_err)?;
    summary.id = id;
    let Some(base_id) = history::baseline_for(&conn, &summary).map_err(db_err)? else {
        return Ok((id, None));
    };
    let old = history::load(&conn, base_id).map_err(db_err)?;
    let new = history::load(&conn, id).map_err(db_err)?;
    Ok((id, Some(history::diff(&old, &new))))
}

#[tauri::command]
fn stop_scan(state: State<'_, ScanState>) {
    state.generation.fetch_add(1, Ordering::SeqCst);
}

#[tauri::command]
async fn rescan_host(ip: String, ports: String, options: Options) -> Result<HostResult, String> {
    let ip: Ipv4Addr = ip.parse().map_err(|_| format!("'{ip}' is not an IP."))?;
    let ports = scanner::parse_ports(&ports)?;
    let cancel = Cancel {
        current: Arc::new(AtomicU64::new(0)),
        generation: 0,
    };
    Ok(scanner::scan_host(ip, &ports, &options.sanitised(), &cancel).await)
}

#[tauri::command]
fn list_scans(db: State<'_, Db>) -> Result<Vec<ScanSummary>, String> {
    history::list(&*db.conn()?).map_err(db_err)
}

#[tauri::command]
fn load_scan(db: State<'_, Db>, id: i64) -> Result<SavedScan, String> {
    history::load(&*db.conn()?, id).map_err(db_err)
}

/// Diff two saved scans, always old -> new regardless of argument order.
#[tauri::command]
fn compare_scans(db: State<'_, Db>, a: i64, b: i64) -> Result<Diff, String> {
    let conn = db.conn()?;
    let (old, new) = (a.min(b), a.max(b));
    let old = history::load(&conn, old).map_err(db_err)?;
    let new = history::load(&conn, new).map_err(db_err)?;
    Ok(history::diff(&old, &new))
}

#[tauri::command]
fn delete_scan(db: State<'_, Db>, id: i64) -> Result<(), String> {
    history::delete(&*db.conn()?, id).map_err(db_err)
}

/// Ask where to save, then write the CSV. Returns the path, or None if the
/// user bailed out of the dialog.
#[tauri::command]
async fn save_csv(app: AppHandle, content: String) -> Result<Option<String>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("CSV", &["csv"])
        .set_file_name("annoyed-scan.csv")
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let path = path.into_path().map_err(|e| e.to_string())?;
    tokio::fs::write(&path, content)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(path.display().to_string()))
}

fn main() {
    fdlimit::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanState::default())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let conn = history::open(&dir.join("history.sqlite"))?;
            app.manage(Db(Mutex::new(conn)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            local_range,
            cidr_range,
            start_scan,
            stop_scan,
            rescan_host,
            list_scans,
            load_scan,
            compare_scans,
            delete_scan,
            save_csv
        ])
        .run(tauri::generate_context!())
        .expect("error while running Very Annoyed IP Scanner");
}
