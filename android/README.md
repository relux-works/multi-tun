# Android

Android client/runtime workspace for the mobile `vless-tun` track.

Current state:

- modular Gradle app shell with `:app`, `:core:*`, `:feature:tunnel`, and `:platform:*`
- MVI-driven tunnel home screen and editor flow
- generic seeded default tunnel profile with no user subscription baked in
- local file-backed persistence for tunnel profiles and selected tunnel
- Android `VpnService` bring-up backed by real `libbox` / `sing-box` runtime
- companion `:observer` app that runs under a separate UID and reports public egress
- current minimum supported Android version: Android 13 / API 33

The current shell is intentionally `tun`-first and does not expose localhost SOCKS, mixed, or HTTP listeners.

## Release / Play Test Track Prep

Desktop-side release automation now lives behind the Go CLI `android-release`.

Bootstrap the local release wiring:

```bash
android-release setup
./android/.scripts/release-setup
```

That creates local-only `android/keystore.properties` and seeds placeholder
macOS Keychain items for:

- `works.relux.android.vlesstun.app/release-store-password`
- `works.relux.android.vlesstun.app/release-key-password`

Generate the Play upload keystore:

```bash
android-release generate-keystore
./android/.scripts/release-generate-keystore
```

Defaults:

- keystore file: `android/keystore/upload.jks`
- key alias: `upload`

Then replace the placeholder Keychain values with the real passwords in Keychain
Access, or via `security add-generic-password -U ...`.

Build the signed test-track bundle:

```bash
android-release bundle
android-release bundle --release-notes "Fixed Android 15 VPN connect crash."
android-release bundle --release-notes-file /absolute/path/to/release-notes.txt
./android/.scripts/release-bundle
```

Output:

- `android/app/build/outputs/bundle/release/app-release.aab`
- `android/app/build/outputs/native-debug-symbols/release/native-debug-symbols.zip`
- `android/app/build/outputs/bundle/release/native-debug-symbols.zip`
- `android/app/build/outputs/bundle/release/release-notes.txt` when `--release-notes` or `--release-notes-file` is provided
- `android/app/build/outputs/mapping/release/mapping.txt`

Notes:

- release builds now run `R8` + resource shrinking, so the bundle embeds the ProGuard mapping file for Play deobfuscation
- if AGP cannot extract native symbols because a vendored `.aar` ships pre-stripped native code, `android-release bundle` falls back to packaging the merged native libs into `native-debug-symbols.zip` for manual Play upload

Manual Play publishing now goes through Gradle Play Publisher via `android-release publish`.

Examples:

```bash
android-release publish --track internal --publisher-json /path/to/google-play-service-account.json
android-release publish --track internal --publisher-json /path/to/google-play-service-account.json --release-notes-file /absolute/path/to/release-notes.txt
./android/.scripts/publish-internal --publisher-json /path/to/google-play-service-account.json
```

Credential options:

- export `ANDROID_PUBLISHER_CREDENTIALS` with the raw JSON content
- or pass `--publisher-json /absolute/path/to/service-account.json`

The publish command reuses the signed `app-release.aab` from `android-release bundle` and uploads it to the requested Play track.
If you pass `--release-notes` or `--release-notes-file`, the same text is also copied to `android/app/build/outputs/bundle/release/release-notes.txt`.

## Real Device Smoke

The stable physical-device lane is preinstall + direct instrumentation, not `connectedDebugAndroidTest`.

```bash
scripts/android/run-device-smoke.sh
scripts/android/run-device-smoke.sh --serial 535a1632
scripts/android/run-device-smoke.sh --skip-install
scripts/android/run-device-smoke.sh \
  --serial 535a1632 \
  --test-class works.relux.vless_tun_app.TunnelHomeEditorStateTest
scripts/android/run-device-smoke.sh \
  --serial 535a1632 \
  --test-class works.relux.vless_tun_app.TunnelEgressSmokeTest \
  --source-inline-vless-from-desktop-config
scripts/android/run-device-suite.sh \
  --serial 535a1632 \
  --source-inline-vless-from-desktop-config
```

What the script does:

- builds `:app:assembleDebug` and `:app:assembleAndroidTest`
- installs `observer-debug.apk`, `app-debug.apk`, and `app-debug-androidTest.apk` with `adb install -r -t`
- runs `adb shell am instrument` for the requested test class
- pulls the latest `UITests` screenshots into `android/app/build/reports/device-smoke/<timestamp>/`

Test split:

- `TunnelHomeSmokeTest#tunnelHomeLoads`: shell-launched `UiAutomator` cold-start smoke
- `TunnelHomeEditorStateTest`: shell-launched Compose regression for editor/save state updates on real devices
- `TunnelConnectSmokeTest`: `VpnService`/TUN connect-disconnect loop
- `TunnelEgressSmokeTest`: cross-UID egress shift via the observer app

`scripts/android/run-device-suite.sh` runs the stable sequence end-to-end. If you pass a tunnel source, it executes home, editor, connect, and egress checks; otherwise it runs the UI-only subset.

On MIUI/Xiaomi this path is more reliable than Gradle-managed `connectedDebugAndroidTest`, which may fail during the install phase with `INSTALL_FAILED_USER_RESTRICTED`.

Verified real-device loop on Xiaomi `535a1632`:

- `TunnelHomeSmokeTest#tunnelHomeLoads` passes
- `TunnelHomeEditorStateTest` passes
- `TunnelConnectSmokeTest` passes and reaches `Connected`
- `TunnelEgressSmokeTest` passes with a separate observer app under another UID
- current captured egress change with the desktop VLESS source:
  - direct: `91.77.167.22 · Russia (RU)`
  - tunneled: `144.31.90.46 · Finland (FI)`
