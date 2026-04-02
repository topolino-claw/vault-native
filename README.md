# Vault Native Stable/b

Cross-platform native app wrapping [Vault Web](https://github.com/topolino-claw/PasswordManagerWeb) via Tauri 2.

## Platforms

- macOS (.dmg)
- Windows (.exe / .msi)
- Linux (.AppImage / .deb)
- Android (.apk / .aab)
- iOS (.ipa) -- requires macOS + Xcode

---

## Prerequisites

1. **Rust** -- install via [rustup](https://rustup.rs/)
2. **Tauri CLI**
   ```bash
   cargo install tauri-cli --version "^2"
   ```
3. **System deps** -- see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS (e.g. `webkit2gtk` on Linux)

---

## Desktop Build

```bash
cargo tauri build
```

Output lands in `src-tauri/target/release/bundle/`.

### Desktop Dev (hot reload)

```bash
cargo tauri dev
```

---

## Android Build

### 1. Install Android toolchain

- **Android Studio** -- https://developer.android.com/studio
- Open Android Studio > **SDK Manager** and install:
  - **SDK Platform**: API 36 (or latest)
  - **SDK Build-Tools**: latest
  - **NDK (Side by side)**: latest
  - **CMake**: latest (from SDK Tools tab)

### 2. Set environment variables

Add these to your shell profile (`~/.zshrc`, `~/.bashrc`, etc.):

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export ANDROID_HOME="$HOME/Library/Android/sdk"
export NDK_HOME="$ANDROID_HOME/ndk/$(ls -1 $ANDROID_HOME/ndk | sort -V | tail -1)"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
```

> **Linux/Windows**: adjust paths accordingly. `ANDROID_HOME` is typically `~/Android/Sdk` on Linux or `%LOCALAPPDATA%\Android\Sdk` on Windows.

Reload your shell:

```bash
source ~/.zshrc
```

### 3. Add Rust Android targets

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

### 4. Initialize Android project (first time only)

```bash
cargo tauri android init
```

This generates `src-tauri/gen/android/`. You only need to run this once. If the directory already exists, skip this step.

### 5. Build

**Debug APK** (faster, for testing):

```bash
cargo tauri android build --debug
```

**Release APK/AAB** (optimized, for distribution):

```bash
cargo tauri android build
```

Output location:

```
src-tauri/gen/android/app/build/outputs/apk/       # .apk
src-tauri/gen/android/app/build/outputs/bundle/     # .aab
```

### 6. Run on device/emulator

```bash
cargo tauri android dev
```

> Make sure a device is connected (`adb devices`) or an emulator is running.

### Signing a release APK

For Play Store or sideloading, you need a keystore:

```bash
keytool -genkey -v -keystore vault-release.keystore -alias vault -keyalg RSA -keysize 2048 -validity 10000
```

Then add signing config to `src-tauri/gen/android/app/build.gradle.kts`:

```kotlin
android {
    signingConfigs {
        create("release") {
            storeFile = file("vault-release.keystore")
            storePassword = "your-password"
            keyAlias = "vault"
            keyPassword = "your-password"
        }
    }
    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

### Troubleshooting

| Problem | Fix |
|---------|-----|
| `NDK_HOME not set` | Make sure `NDK_HOME` points to a valid NDK directory inside `$ANDROID_HOME/ndk/` |
| `SDK not found` | Verify `ANDROID_HOME` is set and the SDK is installed via Android Studio |
| `no connected devices` | Run `adb devices` -- plug in a device with USB debugging on, or start an emulator |
| Build fails on fresh clone | Run `cargo tauri android init` first |
| Gradle sync fails | Open `src-tauri/gen/android/` in Android Studio and let it sync |

---

## iOS Build

Requires macOS + Xcode.

```bash
# First time only
cargo tauri ios init

# Build
cargo tauri ios build

# Dev on simulator
cargo tauri ios dev
```

---

## Testing

The project has two test suites: **JavaScript** (frontend logic) and **Rust** (backend/crypto).

### Run everything

```bash
npm run test:all
```

### JavaScript tests (frontend)

```bash
npm test                  # Run all JS suites
```

Individual suites:

| Command | Suite |
|---------|-------|
| `npm run test:merge` | Deep merge algorithm |
| `npm run test:bip39` | BIP39 key derivation |
| `npm run test:password` | Password generation |
| `npm run test:crypto` | Local encryption (AES-256-GCM) |
| `npm run test:lifecycle` | Vault init/save/load flows |
| `npm run test:nostr` | Nostr relay sync |
| `npm run test:ui` | UI navigation & interactions |
| `npm run test:security` | Security hardening checks |
| `npm run test:import` | JSON import/export |
| `npm run test:e2e` | End-to-end multi-device sync |
| `npm run test:relay` | Real relay integration (requires network) |

### Rust tests (backend)

```bash
npm run test:rust         # Or: cd src-tauri && cargo test
```

Covers:
- **crypto.rs** -- BIP39 mnemonic generation/validation, BIP32 key derivation, NIP-06, AES-256-GCM encrypt/decrypt, PBKDF2, password generation, base64, bech32/npub encoding, backup password encryption
- **nostr_ops.rs** -- Nostr event signing (schnorr), NIP-44 v1/v2 encrypt/decrypt, NIP-04 decrypt, event ID computation
- **state.rs** -- Vault lifecycle (lock/unlock), secret clearing, thread safety, settings serialization

---

## Project Structure

```
vault-native/
  vault/            # Web frontend (from PasswordManagerWeb, unchanged)
  src-tauri/
    src/            # Rust backend (lib.rs, main.rs)
    gen/android/    # Generated Android project (after android init)
    gen/apple/      # Generated iOS project (after ios init)
    tauri.conf.json # Tauri config
    Cargo.toml      # Rust dependencies
```

## Source

The `vault/` directory contains the web app from [PasswordManagerWeb](https://github.com/topolino-claw/PasswordManagerWeb).
All vault JS logic is unchanged. Tauri is a shell -- no JS modifications needed.
