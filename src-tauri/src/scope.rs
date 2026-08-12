//! Filesystem capability scope for the vault commands.
//!
//! Every file the app touches is either inside the user-chosen vault folder or
//! a file the user picked through a NATIVE dialog. Those are the only two ways
//! a path may be given to `read_vault_file` / `write_vault_file` /
//! `append_vault_line` / `list_vault_dir` / `remove_vault_file` /
//! `read_vault_backup`.
//!
//! Why this must exist: the renderer is a webview, and while the CSP keeps
//! remote code out, *any* script execution in the webview would otherwise be
//! arbitrary filesystem access — `withGlobalTauri` hands every page the same
//! commands the app uses. Scope enforcement on the Rust side turns "a bug in
//! the webview = read/write/delete anywhere" into "a bug in the webview =
//! read/write/delete only where the user already chose". That is a containment
//! boundary, not a sandbox: the renderer may still drive dialogs, but it can
//! never silently widen the set of permitted paths — only the user can, by
//! picking something.
//!
//! The authority lives with the dialogs, not the renderer:
//!   1. Native dialog commands (`choose_vault_file`, `choose_vault_dir`,
//!      `open_vault_file(s)`) register their results here as they return them.
//!   2. The permits are persisted in the app-data dir, so the same folder
//!      (desktop) or SAF URI grant (Android) stays usable after a restart
//!      without the renderer having to re-assert anything.
//!   3. Every other command refuses paths that are neither an allowed file
//!      (exact match, canonicalized) nor inside an allowed root directory.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::Manager;
use tauri_plugin_fs::FilePath;

#[derive(Default, Serialize, Deserialize)]
struct Persistent {
    roots: Vec<PathBuf>,
    files: Vec<String>,
}

#[derive(Default)]
pub struct ScopeInner {
    roots: Vec<PathBuf>,
    files: Vec<String>,
}

pub struct VaultScope {
    inner: Mutex<ScopeInner>,
}

impl Default for VaultScope {
    fn default() -> Self {
        VaultScope {
            inner: Mutex::new(ScopeInner::default()),
        }
    }
}

/// Canonical form of a file path, resolving symlinks and `..` as far down the
/// tree as exists. Works for not-yet-created targets (save-dialog output): the
/// furthest existing ancestor is canonicalized and the remaining relative
/// components re-appended, so containment checks are never fooled by a missing
/// leaf but also never fail because the leaf does not exist.
fn canonical_resolved(path: &Path) -> Option<PathBuf> {
    let mut p = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !p.exists() {
        let name = p.file_name()?.to_os_string();
        tail.push(name);
        p = p.parent()?.to_path_buf();
    }
    let mut out = p.canonicalize().ok()?;
    for component in tail.iter().rev() {
        out.push(component);
    }
    Some(out)
}

fn canonical_dir(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

fn is_under(root: &Path, candidate: &Path) -> bool {
    let root_parts: Vec<&std::ffi::OsStr> = root.components().map(|c| c.as_os_str()).collect();
    let cand_parts: Vec<&std::ffi::OsStr> = candidate.components().map(|c| c.as_os_str()).collect();
    if root_parts.len() > cand_parts.len() {
        return false;
    }
    root_parts
        .iter()
        .zip(cand_parts.iter())
        .all(|(a, b)| a == b)
}

// ---------------------------------------------------------------------------
// Pure checks (unit-testable without Tauri)
// ---------------------------------------------------------------------------

/// Can the renderer read/write/append/remove this `FilePath`?
pub fn file_allowed(inner: &ScopeInner, path: &FilePath) -> bool {
    match path {
        FilePath::Path(p) => path_allowed(inner, p),
        FilePath::Url(u) => inner.files.iter().any(|f| f == u.as_str()),
    }
}

/// Can the renderer read/write/append/remove this filesystem path?
pub fn path_allowed(inner: &ScopeInner, path: &Path) -> bool {
    // Exact-match against a dialog-picked file.
    if let Some(canon) = canonical_resolved(path) {
        for stored in &inner.files {
            if let Some(stored_canon) = canonical_resolved(Path::new(stored)) {
                if stored_canon == canon {
                    return true;
                }
            }
        }
        // Contained in a dialog-picked folder.
        if inner.roots.iter().any(|root| is_under(root, &canon)) {
            return true;
        }
    }
    false
}

/// Can the renderer list/scan this directory?
pub fn dir_allowed(inner: &ScopeInner, dir: &Path) -> bool {
    let Some(canon) = canonical_dir(dir) else {
        return false;
    };
    inner.roots.iter().any(|root| is_under(root, &canon))
}

/// Register the folder a picker returned (the conflict-free layout root).
pub fn authorize_root(inner: &mut ScopeInner, dir: &str) {
    if let Some(canon) = canonical_dir(Path::new(dir)) {
        if !inner.roots.iter().any(|r| r == &canon) {
            inner.roots.push(canon);
        }
    }
}

/// Register a single file a picker returned (open-vault, import, export).
pub fn authorize_file(inner: &mut ScopeInner, path: &FilePath) {
    match path {
        FilePath::Path(p) => {
            if canonical_resolved(p).is_some() {
                let raw = p.to_string_lossy().to_string();
                if !inner.files.iter().any(|f| f == &raw) {
                    inner.files.push(raw);
                }
            }
        }
        FilePath::Url(u) => {
            let raw = u.as_str().to_string();
            if !inner.files.iter().any(|f| f == &raw) {
                inner.files.push(raw);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// State + persistence
// ---------------------------------------------------------------------------

fn persist_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("vault-scope.json"))
}

impl VaultScope {
    pub fn load(app: &tauri::AppHandle) -> Result<VaultScope, String> {
        let persisted = persist_path(app)?;
        let mut inner = ScopeInner::default();
        if let Ok(text) = std::fs::read_to_string(&persisted) {
            if let Ok(parsed) = serde_json::from_str::<Persistent>(&text) {
                inner.roots = parsed.roots;
                inner.files = parsed.files;
            }
        }
        Ok(VaultScope {
            inner: Mutex::new(inner),
        })
    }

    pub fn save(&self, app: &tauri::AppHandle) -> Result<(), String> {
        let persisted = persist_path(app)?;
        let inner = self.inner.lock().unwrap();
        let data = Persistent {
            roots: inner.roots.clone(),
            files: inner.files.clone(),
        };
        let text = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
        let tmp = persisted.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &persisted).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn authorize_root(&self, app: &tauri::AppHandle, dir: &str) -> Result<(), String> {
        {
            let mut inner = self.inner.lock().unwrap();
            authorize_root(&mut inner, dir);
        }
        self.save(app)
    }

    pub fn authorize_file(&self, app: &tauri::AppHandle, path: &FilePath) -> Result<(), String> {
        {
            let mut inner = self.inner.lock().unwrap();
            authorize_file(&mut inner, path);
        }
        self.save(app)
    }

    pub fn file_allowed(&self, path: &FilePath) -> bool {
        file_allowed(&self.inner.lock().unwrap(), path)
    }

    pub fn path_allowed(&self, path: &Path) -> bool {
        path_allowed(&self.inner.lock().unwrap(), path)
    }

    pub fn dir_allowed(&self, dir: &Path) -> bool {
        dir_allowed(&self.inner.lock().unwrap(), dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("vault-scope-test-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn paths_inside_a_root_are_allowed() {
        let mut inner = ScopeInner::default();
        let root = scratch("in");
        authorize_root(&mut inner, root.to_str().unwrap());

        assert!(path_allowed(&inner, &root.join("topolino-vault.json")));
        assert!(path_allowed(&inner, &root.join("nested").join("file.json")));
        assert!(path_allowed(&inner, &root));
    }

    #[test]
    fn paths_outside_every_root_are_refused() {
        let mut inner = ScopeInner::default();
        let root = scratch("out");
        authorize_root(&mut inner, root.to_str().unwrap());

        let other = scratch("out-other");
        let victim = other.join("secret.json");
        assert!(!path_allowed(&inner, &victim));

        // Note: `..` is already rejected by vaultfs::reject_traversal at the
        // command layer; scope checks containment regardless.
        assert!(!path_allowed(&inner, &root.join("..").join("secret.json")));
    }

    #[test]
    fn sibling_prefix_does_not_broaden_a_root() {
        let mut inner = ScopeInner::default();
        authorize_root(&mut inner, "/vault/dir");
        // /vault/dir-other is a DIFFERENT directory even though the string
        // prefixes match; canonicalization must not be fooled.
        inner.files.clear();
        inner.roots.clear();
        let dir = scratch("prefix-a");
        let dir2 = scratch("prefix-a2");
        authorize_root(&mut inner, dir.to_str().unwrap());
        assert!(path_allowed(&inner, &dir.join("x.json")));
        assert!(!path_allowed(&inner, &dir2.join("x.json")));
    }

    #[test]
    fn picked_files_are_allowed_even_before_they_exist() {
        let mut inner = ScopeInner::default();
        let dir = scratch("picked");
        // A save-dialog target that does not exist yet.
        let target = dir.join("topolino-vault.json");
        authorize_file(
            &mut inner,
            &FilePath::Path(target.clone()),
        );
        assert!(path_allowed(&inner, &target));
    }

    #[test]
    fn traversal_disguises_are_not_allowed() {
        let inner = ScopeInner::default();
        assert!(!path_allowed(&inner, Path::new("/etc/passwd")));
        assert!(!dir_allowed(&inner, Path::new("/etc")));
    }

    #[test]
    fn allow_empty_perimeter_denies_everything() {
        let inner = ScopeInner::default();
        assert!(!path_allowed(&inner, Path::new("/")));
        assert!(!file_allowed(&inner, &FilePath::Path(PathBuf::from("/"))));
    }
}