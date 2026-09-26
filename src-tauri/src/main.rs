#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod arp;
mod devices;
mod discovery;
mod dns;
mod fdlimit;
mod history;
mod icmp;
mod probe;
mod risk;
mod scanner;
mod tray;
mod vendor;

use devices::Device;
use discovery::Announcements;
use history::{Db, Diff, SavedScan, ScanSummary};
use scanner::{Cancel, HostResult, Options, Range};
use serde::Serialize;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
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
    /// The UI says what we're doing during the quiet opening seconds.
    discovering: bool,
}

/// How long to listen for announcements before sweeping. Most responders
/// answer within a second; this leaves room for the slow ones.
const DISCOVERY_WINDOW: Duration = Duration::from_millis(2500);

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

#[derive(Serialize)]
struct TargetPreview {
    count: usize,
    start: String,
    end: String,
}

/// What a target specification would scan, without scanning it.
#[tauri::command]
fn preview_targets(targets: String) -> Result<TargetPreview, String> {
    let targets = scanner::parse_targets(&targets)?;
    Ok(TargetPreview {
        count: targets.ips.len(),
        start: targets.start,
        end: targets.end,
    })
}

/// Kick off a scan in the background; results stream back as `scan-row`
/// events and a final `scan-done` carrying the saved id and any diff.
#[tauri::command]
fn start_scan(
    app: AppHandle,
    state: State<'_, ScanState>,
    targets: String,
    ports: String,
    threads: usize,
    options: Options,
) -> Result<ScanStarted, String> {
    let targets = scanner::parse_targets(&targets)?;
    let ports = Arc::new(scanner::parse_ports(&ports)?);
    let options = options.sanitised();
    let threads = threads.clamp(1, 1024);

    let generation = state.generation.fetch_add(1, Ordering::SeqCst) + 1;
    let cancel = Cancel {
        current: state.generation.clone(),
        generation,
    };
    let scanner::Targets {
        ips,
        spec,
        start: range_start,
        end: range_end,
    } = targets;
    let total = ips.len();
    let started_at = now_ms();

    tauri::async_runtime::spawn(async move {
        // Listen first: announcements name devices that the sweep can only
        // describe by vendor, and turn up some it would miss entirely.
        let announced = if options.discover {
            Arc::new(discovery::discover(DISCOVERY_WINDOW, &cancel).await)
        } else {
            Arc::new(Announcements::new())
        };

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
            let announced = announced.clone();
            tasks.spawn(async move {
                let mut host = scanner::scan_host(ip, &ports, &options, &cancel).await;
                merge_announcement(&mut host, announced.get(&ip)).await;
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
                targets: spec,
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

    Ok(ScanStarted {
        generation,
        total,
        discovering: options.discover,
    })
}

/// Fold what a device announced about itself into its scan result. A device
/// that answered mDNS or SSDP is alive whatever the probes concluded.
async fn merge_announcement(host: &mut HostResult, announced: Option<&discovery::Announcement>) {
    let Some(announced) = announced else { return };
    if host.hostname.is_empty() && !announced.name.is_empty() {
        host.hostname = announced.name.clone();
    }
    host.discovered = announced.services.clone();
    if !host.alive {
        host.alive = true;
        host.alive_via = "mdns".into();
        scanner::fill_identity(host).await;
    }
}

fn save_and_diff(
    app: &AppHandle,
    mut summary: ScanSummary,
    hosts: &[HostResult],
) -> Result<(i64, Option<Diff>), String> {
    let db = app.state::<Db>();
    let mut conn = db.conn()?;
    let id = history::save(&mut conn, &summary, hosts).map_err(db_err)?;
    devices::record_sightings(&mut conn, hosts, summary.finished_at).map_err(db_err)?;
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
    let options = options.sanitised();
    let mut host = scanner::scan_host(ip, &ports, &options, &cancel).await;
    if options.discover {
        let announced = discovery::discover(DISCOVERY_WINDOW, &cancel).await;
        merge_announcement(&mut host, announced.get(&ip)).await;
    }
    Ok(host)
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

/// Menu-bar summary: the count sits next to the icon, the sentence is the
/// first line of its menu.
#[tauri::command]
fn update_tray(app: AppHandle, count: Option<String>, summary: String) {
    tray::update(&app, count, &summary);
}

/// A native notification, sent from Rust so the page needs no permission of
/// its own. Used for scans the user didn't start by hand.
#[tauri::command]
fn notify(app: AppHandle, title: String, body: String) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|e| format!("Notification refused: {e}"))
}

#[tauri::command]
fn list_devices(db: State<'_, Db>) -> Result<Vec<Device>, String> {
    devices::list(&*db.conn()?).map_err(db_err)
}

/// True once the user has approved anything: until then, flagging every
/// device as unknown would be noise.
#[tauri::command]
fn approvals_in_use(db: State<'_, Db>) -> Result<bool, String> {
    devices::any_approved(&*db.conn()?).map_err(db_err)
}

#[tauri::command]
fn set_device_label(
    db: State<'_, Db>,
    key: String,
    label: String,
    note: String,
) -> Result<(), String> {
    devices::set_label(&*db.conn()?, &key, label.trim(), note.trim(), now_ms()).map_err(db_err)
}

#[tauri::command]
fn set_device_approved(db: State<'_, Db>, key: String, approved: bool) -> Result<(), String> {
    devices::set_approved(&*db.conn()?, &key, approved, now_ms()).map_err(db_err)
}

#[tauri::command]
fn forget_device(db: State<'_, Db>, key: String) -> Result<(), String> {
    devices::forget(&*db.conn()?, &key).map_err(db_err)
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
        .plugin(tauri_plugin_notification::init())
        .manage(ScanState::default())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let conn = history::open(&dir.join("history.sqlite"))?;
            app.manage(Db(Mutex::new(conn)));
            tray::build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Keep the scan loop (and any schedule) alive in the menu bar.
                api.prevent_close();
                tray::hide_on_close(window);
            }
        })
        .invoke_handler(tauri::generate_handler![
            local_range,
            preview_targets,
            start_scan,
            stop_scan,
            rescan_host,
            list_scans,
            notify,
            update_tray,
            list_devices,
            approvals_in_use,
            set_device_label,
            set_device_approved,
            forget_device,
            load_scan,
            compare_scans,
            delete_scan,
            save_csv
        ])
        .build(tauri::generate_context!())
        .expect("error while running Very Annoyed IP Scanner")
        .run(|_app, _event| {
            // Clicking the dock icon after closing the window should bring it
            // back, rather than doing nothing. Reopen is a macOS-only event.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = _event {
                tray::show(_app);
            }
        });
}
