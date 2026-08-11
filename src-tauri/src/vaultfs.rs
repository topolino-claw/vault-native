//! Durable file operations for the vault.
//!
//! The previous implementation opened the vault file with `.truncate(true)`
//! and wrote in place. Between the truncate and the final byte the file is
//! empty or partial on disk, and the seed phrase lives in that file — a crash,
//! a battery death or a Syncthing read landing in that window costs the user
//! every password they own. That is the highest probability-times-severity
//! failure in the whole design, and it is not a cryptographic one.
//!
//! Everything here is built around three rules:
//!
//!   1. Never modify a file in place. Write a sibling temp file, fsync it,
//!      then rename over the target. Rename is atomic within a filesystem, so
//!      a reader sees either the whole old file or the whole new one.
//!   2. Fsync the containing directory after a rename. Without it the rename
//!      itself can be lost on power failure even though the data was durable.
//!   3. Keep the previous generations. Atomicity protects against a torn
//!      write; it does not protect against writing something wrong.
//!
//! Appends (the per-device operation logs) do not need the temp-and-rename
//! dance: they only ever add bytes to the end, so a torn append damages at
//! most the final line, and the log format is line-oriented precisely so that
//! a damaged final line is skipped instead of fatal.
//!
//! Android note: content:// URIs from the SAF picker are not real paths. They
//! support neither sibling temp files nor fsync, so they fall back to a direct
//! write. The store compensates by keeping the operation log as the durable
//! record — see vault/core/store.js.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tauri_plugin_fs::{FilePath, FsExt, OpenOptions};

/// How many previous generations of a file to keep alongside it.
const BACKUP_GENERATIONS: usize = 3;

fn as_real_path(path: &FilePath) -> Option<PathBuf> {
    match path {
        FilePath::Path(p) => Some(p.clone()),
        _ => None,
    }
}

/// Refuse a path that walks upward out of its directory via `..`.
///
/// Every path the app uses is either an OS file-picker result or the chosen
/// vault directory joined with a fixed file name — none contain a parent-dir
/// component, so one that does is a bug or an attempt to reach a file outside
/// the intended location. This is path hygiene, not a sandbox: on its own it
/// does not confine access to the vault directory (a plain absolute path still
/// resolves). Full capability scoping is tracked in ROADMAP.
pub fn reject_traversal(path: &Path) -> Result<(), String> {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("refusing path with a parent-directory (..) component".to_string());
    }
    Ok(())
}

fn temp_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault".to_string());
    name.push_str(".tmp-write");
    path.with_file_name(name)
}

fn backup_path(path: &Path, generation: usize) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault".to_string());
    name.push_str(&format!(".bak{}", generation));
    path.with_file_name(name)
}

/// Fsync the directory holding `path`, making a rename durable.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        // A directory handle opened read-only is enough to fsync it. Failure
        // is not fatal — some filesystems refuse it — so callers ignore the
        // error rather than failing a write that already landed.
        let dir = fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

/// Rotate `file` -> `file.bak1` -> `file.bak2` ... discarding the oldest.
///
/// Runs before a replacement lands, so `.bak1` is always the last-known-good
/// content. Losing a backup rotation must never fail the write itself: a
/// missing backup is a smaller problem than a refused save.
fn rotate_backups(path: &Path) {
    if !path.exists() {
        return;
    }
    for generation in (1..BACKUP_GENERATIONS).rev() {
        let from = backup_path(path, generation);
        let to = backup_path(path, generation + 1);
        if from.exists() {
            let _ = fs::rename(&from, &to);
        }
    }
    let _ = fs::copy(path, backup_path(path, 1));
}

/// Atomically replace a real filesystem path. Kept free of `AppHandle` so the
/// durability rules can be unit-tested without a running Tauri app.
pub fn write_path_atomic(real: &Path, contents: &str, keep_backups: bool) -> Result<(), String> {
    reject_traversal(real)?;
    if keep_backups {
        rotate_backups(real);
    }

    let temp = temp_sibling(real);
    {
        let mut file = fs::File::create(&temp).map_err(|e| e.to_string())?;
        file.write_all(contents.as_bytes())
            .map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;
        // Durable BEFORE the rename: renaming a file whose contents are still
        // in the page cache can leave an empty file after a power loss.
        file.sync_all().map_err(|e| e.to_string())?;
    }

    fs::rename(&temp, real).map_err(|e| {
        let _ = fs::remove_file(&temp);
        e.to_string()
    })?;

    let _ = sync_parent_dir(real);
    Ok(())
}

/// Append one line to a real path, durably.
///
/// If the file does not already end in a newline, one is written first. A
/// torn append (power loss mid-write) leaves a partial line with no
/// terminator; without this, the NEXT append would be concatenated onto that
/// partial line and corrupt itself too — so one interrupted write would cost
/// two operations instead of one. Found by the Monte Carlo suite.
pub fn append_path(real: &Path, line: &str) -> Result<(), String> {
    reject_traversal(real)?;
    let needs_newline = match fs::metadata(real) {
        Ok(meta) if meta.len() > 0 => {
            let mut file = fs::File::open(real).map_err(|e| e.to_string())?;
            use std::io::{Read, Seek, SeekFrom};
            file.seek(SeekFrom::End(-1)).map_err(|e| e.to_string())?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last).map_err(|e| e.to_string())?;
            last[0] != b'\n'
        }
        _ => false,
    };

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(real)
        .map_err(|e| e.to_string())?;
    if needs_newline {
        file.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    if !line.ends_with('\n') {
        file.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    file.flush().map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}

/// Atomically replace `path` with `contents`.
pub fn write_atomic(
    app: &tauri::AppHandle,
    path: FilePath,
    contents: &str,
    keep_backups: bool,
) -> Result<(), String> {
    match as_real_path(&path) {
        Some(real) => write_path_atomic(&real, contents, keep_backups),
        // Opaque URI (Android SAF): no siblings, no fsync. Write directly.
        None => write_direct(app, path, contents, false),
    }
}

/// Append one line, durably. Used for the per-device operation logs.
pub fn append_line(app: &tauri::AppHandle, path: FilePath, line: &str) -> Result<(), String> {
    if let Some(real) = as_real_path(&path) {
        return append_path(&real, line);
    }

    // SAF fallback: read-modify-write, since append mode is unavailable.
    let existing = app.fs().read_to_string(path.clone()).unwrap_or_default();
    let mut next = existing;
    next.push_str(line);
    if !line.ends_with('\n') {
        next.push('\n');
    }
    write_direct(app, path, &next, false)
}

/// Last-resort direct write, for paths that cannot be renamed onto.
fn write_direct(
    app: &tauri::AppHandle,
    path: FilePath,
    contents: &str,
    sync: bool,
) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = app.fs().open(path, options).map_err(|e| e.to_string())?;
    file.write_all(contents.as_bytes())
        .map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    if sync {
        file.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// List file names (not paths) in a directory. Used to discover per-device
/// logs and Syncthing conflict files.
pub fn list_dir(dir: &str) -> Result<Vec<String>, String> {
    reject_traversal(Path::new(dir))?;
    let entries = fs::read_dir(Path::new(dir)).map_err(|e| e.to_string())?;
    let mut names = Vec::new();
    for entry in entries.flatten() {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            names.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    Ok(names)
}

/// Recover the newest readable backup generation of a file, if any.
pub fn read_backup(path: &str) -> Option<String> {
    let real = Path::new(path);
    if reject_traversal(real).is_err() {
        return None;
    }
    for generation in 1..=BACKUP_GENERATIONS {
        if let Ok(text) = fs::read_to_string(backup_path(real, generation)) {
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("vaultfs-test-{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn atomic_write_replaces_content_and_leaves_no_temp_file() {
        let dir = scratch("atomic");
        let target = dir.join("topolino-vault.json");

        write_path_atomic(&target, "first", false).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "first");

        write_path_atomic(&target, "second", false).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "second");

        // A leftover temp file would be replicated by Syncthing as garbage.
        assert!(!temp_sibling(&target).exists(), "temp file must not survive");
    }

    #[test]
    fn backups_rotate_and_keep_the_last_known_good() {
        let dir = scratch("backups");
        let target = dir.join("topolino-vault.json");

        write_path_atomic(&target, "gen1", true).unwrap();
        write_path_atomic(&target, "gen2", true).unwrap();
        write_path_atomic(&target, "gen3", true).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "gen3");
        // .bak1 is always the content immediately before the current one.
        assert_eq!(fs::read_to_string(backup_path(&target, 1)).unwrap(), "gen2");
        assert_eq!(fs::read_to_string(backup_path(&target, 2)).unwrap(), "gen1");
    }

    #[test]
    fn backups_are_bounded() {
        let dir = scratch("bounded");
        let target = dir.join("topolino-vault.json");
        for i in 0..10 {
            write_path_atomic(&target, &format!("gen{}", i), true).unwrap();
        }
        assert!(!backup_path(&target, BACKUP_GENERATIONS + 1).exists());
    }

    #[test]
    fn recovery_reads_the_newest_backup() {
        let dir = scratch("recover");
        let target = dir.join("topolino-vault.json");
        write_path_atomic(&target, "good", true).unwrap();
        write_path_atomic(&target, "alsogood", true).unwrap();

        // Simulate the live file being destroyed by something outside our
        // control — a bad sync, a disk error, a user deleting it.
        fs::write(&target, "").unwrap();

        let recovered = read_backup(target.to_str().unwrap()).unwrap();
        assert_eq!(recovered, "good");
    }

    #[test]
    fn append_creates_then_appends_one_line_at_a_time() {
        let dir = scratch("append");
        let log = dir.join("tv-000000000001.tvlog");

        append_path(&log, "{\"tvlog\":1,\"dev\":\"000000000001\"}").unwrap();
        append_path(&log, "{\"iv\":\"a\",\"p\":\"b\"}").unwrap();
        // Already newline-terminated: must not double up.
        append_path(&log, "{\"iv\":\"c\",\"p\":\"d\"}\n").unwrap();

        let text = fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("tvlog"));
        assert!(!text.contains("\n\n"), "no blank lines between entries");
    }

    #[test]
    fn append_never_rewrites_earlier_bytes() {
        let dir = scratch("append-prefix");
        let log = dir.join("tv-000000000001.tvlog");
        append_path(&log, "one").unwrap();
        let after_first = fs::read_to_string(&log).unwrap();
        append_path(&log, "two").unwrap();
        let after_second = fs::read_to_string(&log).unwrap();

        // The durability argument for line-per-operation rests on this: an
        // append can only ever damage the tail, never the history.
        assert!(after_second.starts_with(&after_first));
    }

    #[test]
    fn list_dir_returns_file_names_only() {
        let dir = scratch("list");
        fs::write(dir.join("topolino-vault.json"), "x").unwrap();
        fs::write(dir.join("tv-000000000001.tvlog"), "y").unwrap();
        fs::create_dir(dir.join("subdir")).unwrap();

        let mut names = list_dir(dir.to_str().unwrap()).unwrap();
        names.sort();
        assert_eq!(names, vec!["topolino-vault.json", "tv-000000000001.tvlog"]);
    }

    #[test]
    fn traversal_paths_are_refused() {
        assert!(reject_traversal(Path::new("/vault/dir/topolino-vault.json")).is_ok());
        assert!(reject_traversal(Path::new("/vault/dir/foo..bar.json")).is_ok());
        assert!(reject_traversal(Path::new("/vault/dir/../../etc/shadow")).is_err());

        // The real entry points must refuse it, not just the helper.
        let dir = scratch("traversal");
        let escape = dir.join("..").join("escape.json");
        assert!(write_path_atomic(&escape, "x", false).is_err());
        assert!(append_path(&escape, "x").is_err());
        // A leftover file must not have been created by the refused write.
        assert!(!escape.exists());
    }
}
