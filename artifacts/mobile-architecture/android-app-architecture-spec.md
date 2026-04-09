# Android App Architecture Spec

Board chain: `EPIC-260408-1iu8sr` -> `STORY-260408-1eti68` -> `TASK-260408-1rnfqx`

## Goal

Build an Android client in the shape users expect from `v2RayTun`, but with a stricter runtime:

- `VpnService` TUN path only
- `sing-box` TUN inbound only
- no localhost SOCKS, mixed, or HTTP listeners
- MVI-driven app state and screen flow
- modular Gradle project with local or self-hosted dependency resolution

This spec is implementation-oriented. A team should be able to scaffold modules and start coding from it.

## Product Shape

The app is split into one Android app shell, one tunnel runtime service, and shared modules:

```text
VlessTunApp
  -> onboarding, profiles, settings, diagnostics, tunnel control
  -> root store / navigation / permissions
  -> binds to TunnelVpnService

TunnelVpnService
  -> VpnService.Builder
  -> sing-box runtime bootstrap
  -> runtime health loop
  -> route and DNS install

Shared Modules
  -> profile and subscription core
  -> config render
  -> persistence and runtime contracts
  -> feature reducers / stores / UI
```

The app owns control plane. The service owns data plane.

## Module Graph

Start with a modular Gradle graph that keeps Android framework dependencies out of the reusable core:

- `:app`
- `:core:model`
- `:core:subscription`
- `:core:render`
- `:core:persistence`
- `:core:runtime-contract`
- `:platform:vpnservice`
- `:platform:singbox`
- `:feature:onboarding`
- `:feature:profiles`
- `:feature:tunnel`
- `:feature:settings`
- `:feature:diagnostics`
- `:testing:shared`
- `:build-logic:convention`

Rules:

- `:core:*` stays platform-neutral where possible.
- `:platform:vpnservice` is the only module allowed to touch `VpnService`.
- `:platform:singbox` is the only module allowed to own Android-specific `sing-box` integration.
- `:core:render` is the only module allowed to own the `sing-box` JSON shape.
- `:feature:*` modules consume contracts and reducers, not raw platform plumbing.

## Dependency Baseline

Use the current repo as the domain baseline:

- [parse.go](/Users/alexis/src/multi-tun/desktop/internal/vless/subscription/parse.go)
- [profile.go](/Users/alexis/src/multi-tun/desktop/internal/vless/model/profile.go)
- [config.go](/Users/alexis/src/multi-tun/desktop/internal/vless/config/config.go)
- [render.go](/Users/alexis/src/multi-tun/desktop/internal/vless/singbox/render.go)
- [android-vless-tun-architecture.md](/Users/alexis/src/multi-tun/artifacts/mobile-architecture/android-vless-tun-architecture.md)

Android dependency policy:

- use a root version catalog for third-party coordinates
- prefer included builds or checked-out internal repos for private libraries
- keep convention plugins in `:build-logic:convention`
- keep `:platform:singbox` replaceable so runtime packaging can change without touching UI modules

The provided GitLab Gradle example was not accessible from this environment, so treat that reference as a style hint, not a locked source of truth.

## App Process vs `VpnService`

Initial decision: keep `TunnelVpnService` in the default app process.

Why:

- simpler state sharing
- no Binder complexity beyond normal service binding
- easier first implementation slice
- lower risk of inventing a localhost bridge out of convenience

Revisit a dedicated `:vpn` process only if later profiling shows memory or crash-isolation benefits. Do not split process boundaries in v1 just to imitate other clients.

### `:app`

Owns:

- source import and refresh
- profile list and profile selection
- connect, disconnect, reconnect intents
- permission flow
- status and diagnostics UI
- persistence writes for control-plane state
- binding to the service and observing runtime state

Does not own:

- packet forwarding
- tunnel sockets
- live DNS and route application

### `:platform:vpnservice`

Owns:

- `VpnService.prepare(...)` preconditions surfaced by the app
- `VpnService.Builder`
- TUN fd creation
- `sing-box` runtime start and stop
- runtime status updates
- recovery after service restart

Does not own:

- onboarding
- profile selection UI
- navigation
- editing subscription sources
- arbitrary local IPC servers

## Control Plane vs Data Plane

Control plane is app-layer only:

- user intents
- selected profile
- rendered config generation
- runtime command issuance
- state observation

Data plane is service-layer only:

- TUN file descriptor ownership
- packet forwarding
- DNS and route install
- runtime health checks

The service must never expose data-plane access over loopback just to make app communication easier.

## MVI State Topology

Use one app-wide root store with feature reducers and a service bridge reducer.

Suggested state domains:

- `AppState`
- `OnboardingState`
- `ProfilesState`
- `TunnelState`
- `SettingsState`
- `DiagnosticsState`
- `RuntimeBridgeState`

Suggested action groups:

- `AppAction`
- `OnboardingAction`
- `ProfilesAction`
- `TunnelAction`
- `SettingsAction`
- `DiagnosticsAction`
- `RuntimeBridgeAction`

Suggested effect boundaries:

- `OnboardingEffect` for source import and validation
- `ProfilesEffect` for fetch, decode, parse, select
- `TunnelEffect` for connect, disconnect, reconnect
- `SettingsEffect` for persistence and capability flags
- `DiagnosticsEffect` for logs and support artifacts
- `RuntimeBridgeEffect` for service binding, state polling, and event fan-out

Keep reducer contracts in feature modules. Keep Android service code out of reducer modules.

## Navigation Structure

Use a single app navigation graph with a stable tunnel home as the steady-state destination.

Suggested route tree:

- `Launch`
- `Onboarding`
- `Profiles`
- `TunnelHome`
- `Settings`
- `Diagnostics`
- `ProfileDetails`

Suggested user flow:

1. `Launch`
2. `Onboarding` if no source configured
3. `Profiles` if source exists but no profile is selected
4. `TunnelHome` as the default connected/disconnected dashboard
5. secondary routes for settings, diagnostics, and profile details

`TunnelVpnService` has no navigation responsibilities.

## Persistence Layout

Suggested app-private storage layout:

```text
files/
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
    service.log
```

Persistence rules:

- app writes control-plane inputs
- service writes runtime outputs
- app never mutates service-owned `status.json` in place
- service never rewrites onboarding or profile selection files

Secrets:

- subscription secrets and auth tokens live in encrypted app storage or keystore-backed storage
- config artifacts may reference secure handles, not raw secrets

## Render Ownership

`:core:render` owns translation from selected profile plus policy into `sing-box` config.

Inputs:

- selected profile
- routing policy
- DNS policy
- Android runtime capability flags

Outputs:

- one rendered `sing-box` config file for the service
- one normalized runtime manifest for app and service

Android adaptations on top of the current desktop renderer:

- do not inherit any macOS launchd, `vpn-core`, or system DNS handoff logic
- keep `network.mode=tun` as the only accepted transport style
- map route/DNS policy onto `VpnService.Builder` ownership instead of desktop process assumptions
- keep TUN-only inbound generation
- no system-proxy fallback mode
- no localhost inbound for debugging

## Tunnel Startup Sequence

Implementation sequence:

1. app loads source, profile, and policy
2. app renders `sing-box` config into app-private storage
3. app requests VPN consent through `VpnService.prepare(...)` if needed
4. app binds to `TunnelVpnService` and sends a connect command
5. service opens `VpnService.Builder`, configures addresses/routes/DNS, and establishes the TUN fd
6. service starts the `sing-box` runtime with the rendered config
7. service publishes `status=connecting`, then `status=connected`
8. app observes runtime state and updates `TunnelState`

Shutdown sequence:

1. app sends disconnect intent
2. service stops `sing-box`
3. service closes the TUN interface
4. service writes terminal status and session metadata
5. app reconciles UI and diagnostics state

## Bridge Contract

The bridge between app and service is Binder/service binding plus persisted runtime state files.

Allowed bridge primitives:

- bound service API
- `StateFlow`/observable service state
- app-private files for control-plane and runtime artifacts
- explicit broadcast or callback hooks if needed for wakeups

Forbidden bridge primitives:

- localhost TCP listeners
- localhost SOCKS
- localhost HTTP APIs
- custom loopback RPC servers

## Banned Patterns

Do not introduce any of these:

- `127.0.0.1` or `::1` proxy listener inside app or service
- `socks`, `mixed`, or `http` `sing-box` inbounds for production runtime
- packet forwarding through loopback as a control workaround
- feature modules importing `VpnService`
- reducers reading or writing raw runtime files directly
- config rendering spread across multiple modules
- fallback `system proxy` mode for “easy bring-up”

## Implementation Milestones

### Milestone 1: Scaffold

- create Gradle settings, version catalog, and convention plugins
- scaffold `:app`, `:core:model`, `:core:subscription`, `:core:render`, `:platform:vpnservice`, `:platform:singbox`
- add base MVI/store setup

### Milestone 2: Shared Core

- port profile models
- port subscription parse/select logic
- port routing policy
- build Android-aware render layer

### Milestone 3: App Shell

- onboarding
- profile list
- tunnel home
- settings
- diagnostics placeholder

### Milestone 4: Service Runtime

- `VpnService` bootstrap
- config file handoff
- `sing-box` TUN runtime startup
- runtime status publication

### Milestone 5: Integration

- connect and disconnect from UI
- restart after app relaunch
- reconnect flow
- diagnostics/log surface

### Milestone 6: Hardening

- error taxonomy
- corrupted-state recovery
- service restart recovery
- device smoke tests

## Testing Plan

Unit tests:

- profile parsing
- render policy
- runtime manifest encoding
- state reducer transitions

Integration tests:

- connect/disconnect state machine
- service binding contract
- runtime file ownership and recovery

UI tests with [android-testing-tools](/Users/alexis/.agents/skills/android-testing-tools/agents/skills/android-testing-tools/SKILL.md):

- onboarding flow
- profile selection flow
- connect/disconnect flow
- diagnostics visibility

Manual smoke tests:

- first VPN consent and first connect
- reconnect after app restart
- service restart recovery
- verify no loopback listener exists during an active session

## First Engineering Slice

The first real implementation slice should be:

1. scaffold `:app`, `:core:model`, `:core:render`, `:platform:vpnservice`, `:platform:singbox`
2. port static profile parsing and render one static config
3. create a minimal `TunnelHome` screen with MVI store
4. wire a fake connect flow into a stub `TunnelVpnService`
5. bring the app to a fake connected state before real `sing-box` runtime work

That gets the project to a bootable vertical slice quickly without corrupting the architecture.

## Bottom Line

Ship an Android app that looks like a polished VPN client, but architect it as:

- MVI app shell
- thin `VpnService` runtime adapter
- shared core/render modules
- bound-service control plane
- TUN-only `sing-box` path
- zero localhost proxy surface

That is the intended implementation spec for `TASK-260408-1rnfqx`.
