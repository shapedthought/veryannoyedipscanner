//! The menu bar presence: how many devices are up, without opening anything.
//!
//! Closing the window hides it rather than quitting, so scheduled scans keep
//! running; the tray menu is how you get it back.

use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{App, AppHandle, Emitter, Manager, Runtime, Window};

const TRAY_ID: &str = "main";

/// The one menu entry whose text changes, kept so scans can update it.
pub struct Status<R: Runtime>(pub Mutex<MenuItem<R>>);

pub fn build(app: &App) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "No scans yet", false, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Scan now", true, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open window", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &PredefinedMenuItem::separator(app)?,
            &scan,
            &open,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::quit(app, Some("Quit"))?,
        ],
    )?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(app.default_window_icon().expect("bundled icon").clone())
        .tooltip("Very Annoyed IP Scanner")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            // The window may be hidden, but its scan loop is still alive.
            "scan" => {
                let _ = app.emit("tray-scan", ());
            }
            "open" => show(app),
            _ => {}
        })
        .build(app)?;

    app.manage(Status(Mutex::new(status)));
    Ok(())
}

pub fn show<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Hide instead of closing, so the app keeps watching. Quit lives in the tray
/// menu (and Cmd-Q still works).
pub fn hide_on_close<R: Runtime>(window: &Window<R>) {
    let _ = window.hide();
}

/// `count` sits next to the icon in the menu bar; `summary` is the first line
/// of the menu.
pub fn update<R: Runtime>(app: &AppHandle<R>, count: Option<String>, summary: &str) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_title(count);
    }
    if let Some(status) = app.try_state::<Status<R>>() {
        if let Ok(item) = status.0.lock() {
            let _ = item.set_text(summary);
        }
    }
}
