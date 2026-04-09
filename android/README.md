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

## Real Device Smoke

The stable physical-device lane is preinstall + direct instrumentation, not `connectedDebugAndroidTest`.

```bash
scripts/android/run-device-smoke.sh
scripts/android/run-device-smoke.sh --serial 535a1632
scripts/android/run-device-smoke.sh --skip-install
scripts/android/run-device-smoke.sh \
  --serial 535a1632 \
  --test-class works.relux.vless_tun_app.TunnelEgressSmokeTest \
  --source-inline-vless-from-desktop-config
```

What the script does:

- builds `:app:assembleDebug` and `:app:assembleAndroidTest`
- installs `observer-debug.apk`, `app-debug.apk`, and `app-debug-androidTest.apk` with `adb install -r -t`
- runs `adb shell am instrument` for `works.relux.vless_tun_app.TunnelHomeSmokeTest`
- pulls the latest `UITests` screenshots into `android/app/build/reports/device-smoke/<timestamp>/`

On MIUI/Xiaomi this path is more reliable than Gradle-managed `connectedDebugAndroidTest`, which may fail during the install phase with `INSTALL_FAILED_USER_RESTRICTED`.

Verified real-device loop on Xiaomi `535a1632`:

- `TunnelConnectSmokeTest` passes and reaches `Connected`
- `TunnelEgressSmokeTest` passes with a separate observer app under another UID
- current captured egress change with the desktop VLESS source:
  - direct: `91.77.167.22 · Russia (RU)`
  - tunneled: `144.31.90.46 · Finland (FI)`
