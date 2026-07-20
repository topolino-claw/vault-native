use std::io::Write;

use tauri_plugin_dialog::DialogExt;
use tauri_plugin_fs::{FilePath, FsExt, OpenOptions};

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
async fn read_vault_file(app: tauri::AppHandle, path: FilePath) -> Result<String, String> {
    app.fs().read_to_string(path).map_err(|e| e.to_string())
}

#[tauri::command]
async fn write_vault_file(
    app: tauri::AppHandle,
    path: FilePath,
    contents: String,
) -> Result<(), String> {
    let is_regular_path = matches!(path, FilePath::Path(_));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = app.fs().open(path, options).map_err(|e| e.to_string())?;
    file.write_all(contents.as_bytes())
        .map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    if is_regular_path {
        file.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut context = tauri::generate_context!();
    #[cfg(mobile)]
    context.set_default_window_icon(None);

    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            choose_vault_file,
            open_vault_file,
            read_vault_file,
            write_vault_file
        ])
        .run(context)
        .expect("error while running vault");
}
