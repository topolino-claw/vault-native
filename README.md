# Vault Native

Offline-first password manager built with Tauri 2. Vault data is encrypted with the master password and stored in a user-selected file that can be synced with tools like Syncthing.

## Platforms
- macOS (.dmg)
- Windows (.exe / .msi)
- Linux (.AppImage / .deb)
- Android (.apk / .aab)
- iOS (.ipa) — requires macOS + Xcode

## Build

Prerequisites: https://v2.tauri.app/start/prerequisites/

```bash
# Desktop
cargo tauri build

# Android (requires Android Studio)
cargo tauri android init
cargo tauri android build

# iOS (requires macOS + Xcode)
cargo tauri ios init
cargo tauri ios build
```

## Development

```bash
# Dev mode (opens webview with hot reload from ../vault/)
cargo tauri dev
```

## Source

The `vault/` directory contains the app UI and vault logic. `src-tauri/` contains the native shell and file commands. Generated Android output is intentionally not kept in the repo.
