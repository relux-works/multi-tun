# iOS App Architecture Spec

Board chain: `EPIC-260408-1lxv8d` -> `STORY-260408-1y9pxn` -> `TASK-260408-1jmy6u`

## Goal

Build an Apple client in the shape users expect from `v2RayTun`, but with a stricter runtime:

- `NetworkExtension` packet tunnel only
- `sing-box` TUN path only
- no localhost SOCKS, mixed, or HTTP listeners
- Relux-driven app state and navigation
- Tuist-managed app + extension workspace

This spec is implementation-oriented. A team should be able to scaffold targets and start coding from it.

## Product Shape

The app is split into two executable targets plus shared packages:

```text
VlessTunApp
  -> onboarding, profiles, settings, diagnostics, tunnel control
  -> Relux root store
  -> IoC/bootstrap
  -> NETunnelProviderManager orchestration

VlessTunPacketTunnel
  -> PacketTunnelProvider
  -> packet flow bridge
  -> sing-box runtime bootstrap
  -> tunnel network settings

Shared Packages
  -> domain models
  -> subscription/profile core
  -> config render
  -> app feature Relux modules
  -> runtime contracts
```

The app owns control plane. The extension owns data plane.

## Targets

Use Tuist to generate at least these targets:

- `App/VlessTunApp`
- `Extensions/VlessTunPacketTunnel`
- `Packages/AppShell`
- `Packages/TunnelCore`
- `Packages/TunnelRuntimeAPI`
- `Packages/TunnelRuntimeApple`
- `Packages/ProfilesFeature`
- `Packages/SettingsFeature`
- `Packages/DiagnosticsFeature`
- `Packages/TestInfrastructure`

Optional later targets:

- `Extensions/VlessTunWidget`
- `Packages/ShareExtensionFeature`

## Package Graph

Mirror the local `relux-sample` split where business logic, UI, and interfaces are separate products.

```text
TunnelCoreModels
TunnelCoreInt
TunnelCoreImpl
TunnelRenderInt
TunnelRenderImpl
TunnelPersistenceInt
TunnelPersistenceImpl
TunnelRuntimeAPI
TunnelRuntimeApple
TunnelControlReluxInt
TunnelControlReluxImpl
TunnelUIAPI
TunnelUI
ProfilesReluxInt
ProfilesReluxImpl
ProfilesUIAPI
ProfilesUI
SettingsReluxInt
SettingsReluxImpl
SettingsUIAPI
SettingsUI
DiagnosticsReluxInt
DiagnosticsReluxImpl
DiagnosticsUIAPI
DiagnosticsUI
AppShell
TestInfrastructure
```

Rules:

- `*Models` contains pure value types only.
- `*Int` contains contracts consumed by other packages.
- `*Impl` contains concrete reducers, effects, services, and adapters.
- `*UI` consumes `swiftui-relux` and exposes screens/components.
- `TunnelRuntimeApple` is the only package allowed to touch `NetworkExtension`.
- `TunnelRenderImpl` is the only package allowed to own the sing-box JSON shape.

## Dependency Baseline

Based on the provided refs and local sample:

- `swift-relux`
- `swift-ioc`
- `swiftui-relux`
- `swiftui-reluxrouter`
- `ios-app-manager` generated Tuist scaffolding
- `ios-testing-tools` for UI validation
- `sing-box-for-apple` or an equivalent vendored Apple runtime integration

`darwin-relux` was not locally confirmed, so treat it as optional until its exact role is pinned down. If it exists as a Darwin runtime helper layer, it should sit below app features and above Apple platform adapters.

## Executable Responsibilities

### `VlessTunApp`

Owns:

- subscription import and refresh
- profile list and profile selection
- tunnel start, stop, reconnect intents
- tunnel status screen
- diagnostics screen
- settings screen
- persistence writes into App Group
- `NETunnelProviderManager` save/load/start/stop orchestration
- app lifecycle recovery after extension reconnect or crash

Does not own:

- packet forwarding
- live TUN packet processing
- in-extension DNS or route application

### `VlessTunPacketTunnel`

Owns:

- reading resolved runtime input from App Group
- starting `sing-box` with TUN config
- applying `NEPacketTunnelNetworkSettings`
- bridging `NEPacketTunnelFlow`
- pushing runtime status back to shared state

Does not own:

- onboarding
- profile selection UI
- navigation
- editing subscription sources
- arbitrary local IPC servers

## Control Plane vs Data Plane

Control plane is host app only:

- user intents
- profile selection
- rendered config generation
- runtime command issuance
- state observation

Data plane is extension only:

- packet flow
- tunnel bootstrap
- route and DNS install
- runtime health loop

The extension must never expose data-plane access over loopback just to make control-plane communication easier.

## Relux State Topology

Use one root `Relux.Store` in the app target, then register feature modules from IoC similarly to `relux-sample`.

Suggested top-level state domains:

- `AppState`
- `ProfilesState`
- `TunnelState`
- `SettingsState`
- `DiagnosticsState`
- `RuntimeBridgeState`

Suggested action groups:

- `AppAction`
- `ProfilesAction`
- `TunnelAction`
- `SettingsAction`
- `DiagnosticsAction`
- `RuntimeBridgeAction`

Suggested effect boundaries:

- `ProfilesEffect` for fetch/decode/select
- `TunnelEffect` for connect/disconnect/reconnect
- `SettingsEffect` for persistence and secure values
- `DiagnosticsEffect` for log and status aggregation
- `RuntimeBridgeEffect` for app-group polling or notification reconciliation

## Navigation Structure

Use `ReluxRouter` via `swiftui-reluxrouter` in the app target only.

Suggested route tree:

- `LaunchRoute`
- `OnboardingRoute`
- `ProfilesRoute`
- `TunnelHomeRoute`
- `SettingsRoute`
- `DiagnosticsRoute`
- `ProfileDetailsRoute`

Suggested user flow:

1. `LaunchRoute`
2. `OnboardingRoute` if no source configured
3. `ProfilesRoute` if source exists but no profile selected
4. `TunnelHomeRoute` as the steady-state screen
5. secondary pushes to settings, diagnostics, profile details

The extension has no router.

## Persistence and App Group Layout

Create one App Group shared container for app + extension.

Suggested layout:

```text
AppGroup/
  config/
    source.json
    selected-profile.json
    rendered-singbox.json
  runtime/
    command.json
    status.json
    session.json
  cache/
    subscription-snapshot.json
    profiles-index.json
  logs/
    app.log
    extension.log
```

Persistence rules:

- app writes control-plane inputs
- extension writes runtime outputs
- app never edits extension-owned status files in place
- extension never edits subscription source or profile selection

Secrets:

- auth tokens or subscription secrets go to Keychain
- App Group files may reference Keychain item names, not raw secrets

## Render Ownership

`TunnelRenderImpl` owns translation from selected profile plus policy into sing-box config.

Inputs:

- selected profile
- routing policy
- DNS policy
- Apple runtime capability flags

Outputs:

- one rendered sing-box config file for the extension
- one normalized runtime manifest for the app and extension

Apple adaptations required on top of the current desktop design:

- do not rely on a stable `interface_name`
- do not rely on `strict_route`
- keep TUN-only inbound generation
- no system-proxy fallback mode
- no localhost inbound for debugging

## Tunnel Startup Sequence

Implementation sequence:

1. app loads current source, profile, and policy
2. app renders sing-box config into App Group
3. app writes runtime command manifest with desired session parameters
4. app loads or creates `NETunnelProviderManager`
5. app starts the packet tunnel
6. extension reads command manifest and rendered config
7. extension boots `sing-box` TUN runtime
8. extension applies `NEPacketTunnelNetworkSettings`
9. extension writes `status=connected` plus session metadata
10. app observes status and updates `TunnelState`

Shutdown sequence:

1. app sends disconnect intent
2. manager stops tunnel
3. extension tears down sing-box and packet flow
4. extension writes terminal status
5. app reconciles UI and keeps logs/artifacts

## Bridge Contract

The bridge between app and extension is file-based plus official NetworkExtension control APIs.

Allowed bridge primitives:

- `NETunnelProviderManager`
- App Group files
- Darwin notifications if needed for wakeups

Forbidden bridge primitives:

- localhost TCP listeners
- localhost SOCKS
- localhost HTTP APIs
- custom loopback RPC servers

## Banned Patterns

Do not introduce any of these:

- `127.0.0.1` or `::1` proxy listener inside app or extension
- `socks`, `mixed`, or `http` sing-box inbounds for production runtime
- packet forwarding through loopback as a control workaround
- feature code importing `NetworkExtension`
- UI modules reading raw App Group files directly
- extension writing user-editable settings
- tunnel config rendering spread across multiple packages

## Implementation Milestones

### Milestone 1: Scaffold

- generate Tuist workspace
- create app target and packet tunnel target
- wire `swift-relux`, `swift-ioc`, `swiftui-reluxrouter`
- create App Group and entitlements

### Milestone 2: Shared Core

- port profile models
- port subscription parse/select logic
- port routing policy
- build Apple-aware render layer

### Milestone 3: Host App Shell

- onboarding
- profile list
- tunnel home
- settings
- diagnostics placeholder

### Milestone 4: Extension Runtime

- packet tunnel bootstrap
- read shared config
- start sing-box TUN runtime
- write runtime status

### Milestone 5: Integration

- start/stop flow from UI
- persistence recovery
- reconnect after app relaunch
- diagnostics/log surface

### Milestone 6: Hardening

- error taxonomy
- corrupted state recovery
- background reconnect policy
- device smoke tests

## Testing Plan

Unit tests:

- profile parsing
- render policy
- app-group manifest encoding
- runtime status decoding

Integration tests:

- manager configuration
- app-group handoff
- startup/shutdown state machine

UI tests with `ios-testing-tools`:

- onboarding flow
- profile selection flow
- connect/disconnect flow
- diagnostics visibility

Manual smoke tests:

- start tunnel on fresh install
- reconnect after app restart
- recover after extension crash
- verify no loopback listener is present

## First Engineering Slice

The first real implementation slice should be:

1. scaffold app + packet tunnel targets with Tuist
2. create `TunnelCoreModels`, `TunnelRenderImpl`, `TunnelRuntimeAPI`, `TunnelRuntimeApple`
3. wire `AppShell` with a minimal Relux store
4. render a static config and pass it to the extension
5. bring the extension to a fake connected state before real sing-box runtime work

That gets the project to a bootable vertical slice fast without contaminating the architecture.

## Bottom Line

Ship an app that looks like a polished Apple VPN client, but architect it as:

- Relux app shell
- thin PacketTunnelProvider runtime
- shared render/core packages
- App Group control plane
- TUN-only sing-box path
- zero localhost proxy surface

That is the intended implementation spec for `TASK-260408-1jmy6u`.
