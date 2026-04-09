# Android Emulator Tunnel Verification

Board chain: `EPIC-260408-1iu8sr / STORY-260409-hmbsc8 / TASK-260409-zointz`

Date: 2026-04-09

## Highlights

- The current Android slice cannot yet prove a real VLESS TUN session. [TunnelVpnService](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelVpnService.kt#L20) is still backed by [FakeSingboxRuntime](/Users/alexis/src/multi-tun/android/platform/singbox/src/main/kotlin/works/relux/vless_tun_app/platform/singbox/FakeSingboxRuntime.kt#L9) and never calls `VpnService.Builder.establish()`.
- The repo already has the right control-plane seam for verification: [MainActivity](/Users/alexis/src/multi-tun/android/app/src/main/java/works/relux/vless_tun_app/MainActivity.kt#L40) requests VPN consent, binds through [TunnelServiceConnector](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelServiceConnector.kt#L22), and observes [TunnelRuntimeSnapshot](/Users/alexis/src/multi-tun/android/core/runtime-contract/src/main/kotlin/works/relux/vless_tun_app/core/runtime/TunnelRuntimeSnapshot.kt#L12).
- The current `androidTest` coverage is only a screen-load smoke test in [TunnelHomeSmokeTest](/Users/alexis/src/multi-tun/android/app/src/androidTest/kotlin/works/relux/vless_tun_app/TunnelHomeSmokeTest.kt#L7). It does not verify consent, connected state, TUN bring-up, routed traffic, or localhost listener absence.
- Inference from the local toolkit: the existing UIAutomator Page Objects are not fully reliable yet because the app uses Compose `testTag(...)` in [TunnelHomeScreen](/Users/alexis/src/multi-tun/android/feature/tunnel/src/main/kotlin/works/relux/vless_tun_app/feature/tunnel/TunnelHomeScreen.kt#L39) and `By.res(...)` in [TunnelHomePage](/Users/alexis/src/multi-tun/android/app/src/androidTest/kotlin/works/relux/vless_tun_app/pages/TunnelHomePage.kt#L19), but [android-testing-tools](/Users/alexis/.agents/skills/android-testing-tools/agents/skills/android-testing-tools/SKILL.md) requires `testTagsAsResourceId = true` on the root composable and [MainActivity](/Users/alexis/src/multi-tun/android/app/src/main/java/works/relux/vless_tun_app/MainActivity.kt#L32) does not add it.
- The recommended strategy is a three-lane pyramid:
  - service/runtime tests for deterministic state publication and listener auditing
  - a gated live emulator suite for actual VPN consent, TUN establish, and routed network probes
  - a small manual smoke checklist for first-run consent and external sanity checks

## Fact-Checked Current State

### Verified facts from this repo

1. The app already follows the Android VPN consent entrypoint. [MainActivity](/Users/alexis/src/multi-tun/android/app/src/main/java/works/relux/vless_tun_app/MainActivity.kt#L49) launches the `VpnService.prepare(...)` intent through `ActivityResultContracts.StartActivityForResult`, marks permission-required state, and only calls `connector.connect(...)` after `RESULT_OK`.
2. The service manifest is correctly declared as a VPN service. [AndroidManifest.xml](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/AndroidManifest.xml#L5) sets `android.permission.BIND_VPN_SERVICE` and the `android.net.VpnService` intent filter.
3. Runtime state is already modeled as `Disconnected`, `PermissionRequired`, `Connecting`, `Connected`, `Disconnecting`, and `Error` in [TunnelRuntimeSnapshot.kt](/Users/alexis/src/multi-tun/android/core/runtime-contract/src/main/kotlin/works/relux/vless_tun_app/core/runtime/TunnelRuntimeSnapshot.kt#L3).
4. The service publishes runtime snapshots through a bound local binder. [TunnelVpnService.LocalBinder](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelVpnService.kt#L43) exposes `snapshots()`, `connect(...)`, and `disconnect()`, and [TunnelServiceConnector](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelServiceConnector.kt#L52) forwards those snapshots into app state.
5. The current runtime is explicitly stubbed. [TunnelVpnService](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelVpnService.kt#L22) instantiates `FakeSingboxRuntime`, and [FakeSingboxRuntime](/Users/alexis/src/multi-tun/android/platform/singbox/src/main/kotlin/works/relux/vless_tun_app/platform/singbox/FakeSingboxRuntime.kt#L14) only delays and returns a synthetic `Connected` snapshot.
6. The current render layer already contains one static guard against localhost bridges. [TunnelConfigRendererTest](/Users/alexis/src/multi-tun/android/core/render/src/test/kotlin/works/relux/vless_tun_app/core/render/TunnelConfigRendererTest.kt#L10) asserts the rendered JSON contains a TUN inbound and does not contain `127.0.0.1`, `::1`, `socks`, `mixed`, or `http`.
7. The local Android testing toolkit is already wired into the build. [android/settings.gradle.kts](/Users/alexis/src/multi-tun/android/settings.gradle.kts#L17) includes the local toolkit build, and [android/app/build.gradle.kts](/Users/alexis/src/multi-tun/android/app/build.gradle.kts#L61) depends on `com.uitesttools:screenshot-kit` and `com.uitesttools:uitest-kit`.

### Verified external platform facts

- Android documents that `VpnService.prepare(...)` returns `null` when the app is already prepared or the user has already consented, otherwise it returns a system activity intent for consent. Source: [Android `VpnService` reference](https://developer.android.com/reference/android/net/VpnService#prepare(android.content.Context)) and [Android VPN guide](https://developer.android.com/develop/connectivity/vpn).
- Android documents that `VpnService.Builder.establish()` creates the VPN interface and returns `null` if the app is not prepared. Source: [Android `VpnService.Builder.establish()` reference](https://developer.android.com/reference/android/net/VpnService.Builder#establish()).

## Recommended Verification Strategy

### Test lanes

| Lane | Runs when | What it proves | What it must not try to prove |
| --- | --- | --- | --- |
| Service/runtime tests | every PR | binder state publication, TUN-establish bookkeeping, listener-audit parser, rendered-config bans | public internet routing through the real VLESS tunnel |
| Live emulator tunnel suite | gated CI, nightly, or explicit label | real consent handling, real `Builder.establish()`, real `sing-box` runtime startup, real app-side probe routed through the tunnel, no loopback listeners during an active session | fresh-device first-run ergonomics across every Android skin/locale |
| Manual smoke | before release and after major runtime changes | clean-emulator first consent, physical-device sanity, external operator validation | repeatable PR gating |

### Why the split is necessary

- The repo’s current stub runtime means a green UI test can only prove screen state, not a real tunnel.
- A true tunnel test needs live secrets, a running VLESS backend, and a reachable network probe endpoint. That is too expensive and too flaky for every PR.
- The consent dialog is system UI, not app UI. It should be handled once for seeded CI images and only interactively driven when seeding or debugging.

## VPN Consent: Automate Or Gate

### Preferred path: seeded consent snapshot

Use a dedicated emulator image or boot snapshot where the app has already been granted VPN consent once.

Reasoning:

- Android says `VpnService.prepare(...)` returns `null` after prior consent, so the steady-state test path can skip the dialog entirely.
- This keeps the normal live suite deterministic and avoids locale-specific UIAutomator selectors.

Operational rules:

1. Boot a named CI AVD with snapshots enabled.
2. Install the debug app without wiping app data between seed and test runs.
3. Run a one-time consent seeding flow on that AVD.
4. Save the seeded state and reuse it for the live tunnel suite.
5. Do not call `pm clear`, uninstall the app, or recreate the AVD before the live suite.

### Fallback path: UIAutomator consent handler

For local development and for the one-time seed job, add a `VpnConsentPage` Page Object in `androidTest` that:

- waits for the system VPN dialog
- captures a screenshot before approval
- taps the affirmative button
- returns control to the app and waits for the tunnel screen to resume

Constraints:

- Keep the emulator locale fixed to English for this flow.
- Treat this handler as a fallback and seeding tool, not the default PR lane.
- Do not rely on unsupported shell hacks or device-owner flows for normal verification.

## Connected State Publication

### Service-side contract

The real runtime should publish more than just a string detail. Extend [TunnelRuntimeSnapshot](/Users/alexis/src/multi-tun/android/core/runtime-contract/src/main/kotlin/works/relux/vless_tun_app/core/runtime/TunnelRuntimeSnapshot.kt#L12) with fields that let tests prove real bring-up:

- `sessionId`
- `vpnPrepared`
- `tunEstablished`
- `tunInterfaceName`
- `connectedAt`
- `lastProbe`
- `forbiddenListeners`
- `lastError`

The state machine should become:

1. `Disconnected`
2. `PermissionRequired` when `VpnService.prepare(...)` returns a non-null intent
3. `Connecting` after consent is satisfied and the service begins work
4. `Connecting(tunEstablished=true)` immediately after `Builder.establish()` succeeds
5. `Connected` only after the real `sing-box` runtime has started and the service health check passes
6. `Error` on any establish or runtime failure

### How to verify it

Service/runtime tests:

- bind directly to `TunnelVpnService`
- trigger `connect(...)`
- await `Connecting`
- assert a published transition that proves `Builder.establish()` succeeded
- await `Connected`
- assert the terminal snapshot contains `sessionId`, `tunEstablished=true`, and no `lastError`

UI/instrumentation tests:

- tap the primary connect button
- assert the status card transitions from `Disconnected` to `Connecting` to `Connected`
- assert the detail text is driven by the published snapshot, not by hard-coded UI timing

Recommended secondary oracle:

- persist each runtime snapshot to app-private `runtime/status.json` as already suggested by [android-app-architecture-spec.md](/Users/alexis/src/multi-tun/artifacts/mobile-architecture/android-app-architecture-spec.md#L217)
- service/runtime tests should assert binder state and file state match

## Real Network Probe Through The Tunnel

### Core rule

The probe must originate from normal app traffic, not from a socket that the VPN service protects from the tunnel.

Why:

- service control sockets often use `VpnService.protect(...)` or explicit underlying-network routing to avoid feedback loops
- a probe sent over those protected sockets proves upstream reachability, not that ordinary app traffic is routed through the VPN

### Recommended probe flow

1. Before connect, run an HTTPS probe from the app process to a controlled echo endpoint and record baseline origin metadata.
2. Connect the tunnel and wait for `Connected`.
3. Run the same HTTPS probe again from the app process.
4. Assert:
   - the second response succeeded
   - the observed origin changed from the baseline
   - the tunneled origin matches an allowlist for the expected VPN egress or provider-owned ASN/range
5. Disconnect and run the probe a third time to confirm the origin reverts away from the tunnel egress.

### Probe endpoint requirements

The endpoint should return structured JSON with at least:

- observed client IP
- observed ASN or region metadata
- request timestamp
- optional signed session echo so the test can correlate results

Do not use:

- `10.0.2.2`
- localhost callbacks
- emulator-host-only endpoints

Those paths do not prove internet traffic crossed the VPN tunnel.

### Test placement

Belongs in the gated live emulator suite, not in unit tests and not in the cheap PR lane.

## No Localhost Proxy Listeners During An Active Session

### Two checks are required

1. Static config check
2. Runtime socket audit

The repo already has the first one in [TunnelConfigRendererTest](/Users/alexis/src/multi-tun/android/core/render/src/test/kotlin/works/relux/vless_tun_app/core/render/TunnelConfigRendererTest.kt#L10). Keep it and expand it once the renderer becomes dynamic.

### Runtime socket audit

During an active connected session, instrumentation should run a shell-side audit of:

- `/proc/net/tcp`
- `/proc/net/tcp6`
- `/proc/net/udp`
- `/proc/net/udp6`

Audit logic:

1. Resolve the target app UID from package metadata.
2. Parse socket tables.
3. Filter rows owned by that UID.
4. Fail if any listener or bound proxy-like socket is attached to:
   - `127.0.0.1:*`
   - `::1:*`
   - `localhost`-equivalent loopback addresses

This is the right place to catch accidental `socks`, `mixed`, `http`, debug proxy, or loopback RPC regressions that a render-only test would miss.

Recommended publication:

- include the parsed `forbiddenListeners` list in the service diagnostics snapshot
- keep the instrumentation test authoritative for the shell-level audit

### Manual backstop

Keep one manual smoke check that repeats the socket audit from `adb shell` during a live session. This remains useful if a future Android release changes `/proc` visibility or shell formatting.

## Where Each Verification Belongs

| Concern | Instrumentation/UI tests | Service/runtime tests | Manual smoke |
| --- | --- | --- | --- |
| Screen loads, stable tags, screenshots | yes | no | optional |
| VPN consent dialog handling | yes, but mainly for seed/fallback | no | yes |
| `prepare()` null-after-consent happy path | yes | yes via wrapper/injected facade | optional |
| `Builder.establish()` succeeded | no direct UI assertion | yes | optional |
| `Connecting -> Connected` publication on binder/file state | UI reflects it | yes, primary ownership | optional |
| App-side routed network probe | yes, gated live suite | no | yes |
| Rendered config contains no localhost inbounds | no | yes | no |
| Runtime socket audit for loopback listeners | can trigger it | yes, parser ownership | yes |
| Fresh emulator first-run UX | no | no | yes |

## How To Use `android-testing-tools` In This Project

Use the local toolkit that is already included by [android/settings.gradle.kts](/Users/alexis/src/multi-tun/android/settings.gradle.kts#L17) and [android/app/build.gradle.kts](/Users/alexis/src/multi-tun/android/app/build.gradle.kts#L61).

Project-specific guidance:

1. Keep the current Page Object shape from [TunnelHomePage](/Users/alexis/src/multi-tun/android/app/src/androidTest/kotlin/works/relux/vless_tun_app/pages/TunnelHomePage.kt#L9), but add:
   - `VpnConsentPage`
   - `TunnelDiagnosticsPage`
   - helper methods for waiting on `Connecting` and `Connected`
2. Keep using `BaseUiTestSuite` from the toolkit for:
   - app launch
   - structured screenshots
   - `UiDevice` access to system dialogs
3. Add screenshots at:
   - app launched
   - consent dialog visible
   - connecting state
   - connected state
   - disconnected state after teardown
4. Preserve the current tag naming style in [TunnelHomeTags](/Users/alexis/src/multi-tun/android/feature/tunnel/src/main/kotlin/works/relux/vless_tun_app/feature/tunnel/TunnelHomeTags.kt#L3). It already matches the toolkit’s structured naming approach.
5. Add `testTagsAsResourceId = true` at the root composable before expanding UIAutomator usage. This is required by the local toolkit documentation in [android-testing-tools/SKILL.md](/Users/alexis/.agents/skills/android-testing-tools/agents/skills/android-testing-tools/SKILL.md#L260).

## Recommended Test Inventory

### Service/runtime tests

- `TunnelRuntimeContractTest`
  - verifies `Disconnected -> Connecting -> Connected`
  - verifies `tunEstablished=true` is published only after `Builder.establish()`
- `TunnelStatusPersistenceTest`
  - verifies binder snapshot equals persisted `runtime/status.json`
- `TunnelListenerAuditParserTest`
  - verifies socket-table parsing catches loopback listeners and ignores normal outbound sockets
- `TunnelRenderGuardsTest`
  - extends current localhost inbound bans

### Gated live emulator tests

- `TunnelConnectLiveTest`
  - seeded-consent connect flow
  - waits for `Connected`
  - asserts disconnect works
- `TunnelProbeRoutingLiveTest`
  - baseline probe
  - connected probe
  - disconnect probe
- `TunnelNoLocalhostListenersLiveTest`
  - runs the shell audit during active connection

### Manual smoke

- clean emulator, no prior consent, verify the first-run dialog text and flow
- physical device sanity check after any major runtime packaging change
- operator-run `adb shell` socket audit during one live session

## Implementation Order

1. Replace `FakeSingboxRuntime` with an injectable real runtime interface plus a deterministic fake for tests.
2. Extend `TunnelRuntimeSnapshot` to publish real establish/probe/listener fields.
3. Persist runtime snapshots to app-private storage.
4. Add `testTagsAsResourceId = true` to the root Compose surface.
5. Add service/runtime tests for binder transitions and listener-audit parsing.
6. Build the seeded emulator consent flow.
7. Add the gated live probe and loopback-listener suites.

## Bottom Line

Do not treat a green UI smoke test as proof that Android `vless-tun` works. The automated proof must combine:

- real `VpnService.prepare(...)` handling
- real `Builder.establish()` evidence
- published connected state from service to app
- a real app-originated network probe whose observed egress changes under the tunnel
- a runtime shell audit proving no loopback proxy listeners appear while the tunnel is active

That split gives this repo a cheap deterministic lane for daily work and a credible gated lane that proves the Android VLESS TUN tunnel actually starts.
