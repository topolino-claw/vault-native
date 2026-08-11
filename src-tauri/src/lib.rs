mod vaultfs;

use tauri_plugin_dialog::DialogExt;
use tauri_plugin_fs::{FilePath, FsExt};

fn dialog_path_to_string(path: FilePath) -> String {
    path.to_string()
}

#[tauri::command]
async fn choose_vault_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    Ok(app
        .dialog()
        .file()
        .add_filter("Topolino Vault", &["topolino-vault", "json"])
        .set_file_name("topolino-vault.json")
        .blocking_save_file()
        .map(dialog_path_to_string))
}

/// Pick a folder rather than a file.
///
/// A folder is what the conflict-free layout needs: the app writes its own
/// per-device log beside the shared snapshot, and must be able to list
/// siblings to discover other devices' logs and Syncthing conflict files.
/// A single-document URI allows neither, which is why Android — where this
/// picker is unavailable — uses the single-file container instead.
#[tauri::command]
async fn choose_vault_dir(app: tauri::AppHandle) -> Result<Option<String>, String> {
    // Desktop only. tauri-plugin-dialog exposes no folder picker on Android —
    // its SAF integration returns a single-document URI, which cannot list or
    // create siblings. The frontend falls back to the single-file container
    // there (vault/core/transports.js), so this returns an error rather than
    // pretending a folder was declined.
    #[cfg(desktop)]
    {
        Ok(app
            .dialog()
            .file()
            .blocking_pick_folder()
            .map(dialog_path_to_string))
    }
    #[cfg(mobile)]
    {
        let _ = app;
        Err("Folder selection is not available on this platform".to_string())
    }
}

#[tauri::command]
async fn open_vault_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    Ok(app
        .dialog()
        .file()
        .add_filter("Topolino Vault", &["topolino-vault", "json"])
        .blocking_pick_file()
        .map(dialog_path_to_string))
}

#[tauri::command]
async fn open_vault_files(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    Ok(app
        .dialog()
        .file()
        .add_filter("Topolino Vault", &["topolino-vault", "json"])
        .blocking_pick_files()
        .unwrap_or_default()
        .into_iter()
        .map(dialog_path_to_string)
        .collect())
}

#[tauri::command]
async fn read_vault_file(app: tauri::AppHandle, path: FilePath) -> Result<String, String> {
    if let FilePath::Path(p) = &path {
        vaultfs::reject_traversal(p)?;
    }
    app.fs().read_to_string(path).map_err(|e| e.to_string())
}

/// Atomic, durable replace. `keep_backups` rotates previous generations and
/// should be true for anything whose loss is unrecoverable (the snapshot and
/// the keyslot file); operation logs do not need it because they are
/// append-only and never rewritten except during compaction.
#[tauri::command]
async fn write_vault_file(
    app: tauri::AppHandle,
    path: FilePath,
    contents: String,
    keep_backups: Option<bool>,
) -> Result<(), String> {
    vaultfs::write_atomic(&app, path, &contents, keep_backups.unwrap_or(true))
}

#[tauri::command]
async fn append_vault_line(
    app: tauri::AppHandle,
    path: FilePath,
    line: String,
) -> Result<(), String> {
    vaultfs::append_line(&app, path, &line)
}

#[tauri::command]
async fn list_vault_dir(dir: String) -> Result<Vec<String>, String> {
    vaultfs::list_dir(&dir)
}

#[tauri::command]
async fn remove_vault_file(path: String) -> Result<(), String> {
    vaultfs::reject_traversal(std::path::Path::new(&path))?;
    std::fs::remove_file(&path).map_err(|e| e.to_string())
}

/// Newest readable backup generation, for disaster recovery.
#[tauri::command]
async fn read_vault_backup(path: String) -> Result<Option<String>, String> {
    Ok(vaultfs::read_backup(&path))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // `mut` is only used on mobile (set_default_window_icon below); allow it so
    // desktop builds don't warn.
    #[cfg_attr(desktop, allow(unused_mut))]
    let mut context = tauri::generate_context!();
    #[cfg(mobile)]
    context.set_default_window_icon(None);

    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            choose_vault_file,
            choose_vault_dir,
            open_vault_file,
            open_vault_files,
            read_vault_file,
            write_vault_file,
            append_vault_line,
            list_vault_dir,
            remove_vault_file,
            read_vault_backup
        ])
        .run(context)
        .expect("error while running vault");
}
