# Vault Native

Cross-platform native app wrapping [Vault Web](https://github.com/topolino-claw/PasswordManagerWeb) via Tauri 2.

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

The `vault/` directory contains the web app from [PasswordManagerWeb](https://github.com/topolino-claw/PasswordManagerWeb).
All vault JS logic is unchanged. Tauri is a shell — no JS modifications.
