# Android VLESS TUN Architecture Memo

Scope: `TASK-260408-1g45pw` / `STORY-260408-2ode9k` / `EPIC-260408-1iu8sr`

Goal: build an Android `vless-tun` client around `sing-box` TUN only. `localhost` listeners are forbidden. Do not add `socks`, `mixed`, or `http` inbounds as a bridge between UI and tunnel runtime.

## Decision

The Android app should reuse the same high-level shape already proven in the desktop `vless-tun` core:

- subscription normalization and multi-line `vless://` parsing from [desktop/internal/vless/subscription/parse.go](/Users/alexis/src/multi-tun/desktop/internal/vless/subscription/parse.go)
- immutable profile data in [desktop/internal/vless/model/profile.go](/Users/alexis/src/multi-tun/desktop/internal/vless/model/profile.go)
- config policy and TUN-only validation in [desktop/internal/vless/config/config.go](/Users/alexis/src/multi-tun/desktop/internal/vless/config/config.go)
- `sing-box` config rendering in [desktop/internal/vless/singbox/render.go](/Users/alexis/src/multi-tun/desktop/internal/vless/singbox/render.go)

The desktop `session.go` lifecycle is not portable as-is. It is tied to macOS launchd, privileged helpers, and system DNS handoff. Android needs its own `VpnService` runtime and foreground-service lifecycle.

## Recommended Module Graph

Keep the Android project modular from day one. Suggested Gradle graph:

- `:app` for navigation, MVI wiring, permission flow, and user-facing screens
- `:core:model` for profile and config models
- `:core:subscription` for subscription fetch/normalize/parse/select
- `:core:render` for `sing-box` config rendering and validation
- `:core:storage` for cache, profile persistence, and runtime state
- `:platform:vpnservice` for the Android `VpnService` lifecycle, binder contract, and foreground notification
- `:platform:singbox` for the embedded `sing-box` runtime or library wrapper
- `:feature:profiles` for subscription/profile UI
- `:feature:tunnel` for tunnel start/stop/status UI
- `:testing:shared` for reusable test fixtures and fake tunnel state

If this repo uses a single app module plus feature modules, keep the domain layer free of Android UI classes and keep the service layer thin.

## Process Split

Split responsibility between two processes:

- `app process` owns UI state, profile selection, setup, errors, and user actions
- `VpnService` process owns the live tunnel, route/dns setup, and the `sing-box` lifecycle

Do not route traffic through a local loopback proxy to cross that boundary. Use the service binder, shared state, or files only for control-plane state, not for packet forwarding.

## Reusable Multi-Tun Pieces

The reusable pieces are the domain rules, not the macOS runtime:

- subscription payload normalization and `vless://` parsing
- profile identity, display name, and endpoint derivation
- config validation and policy defaults
- bypass suffix/exclude routing policy
- `sing-box` outbound construction for VLESS Reality / TLS / gRPC variants

The desktop render layer is a good baseline for the JSON shape, but Android should adapt it to the mobile client runtime rather than inheriting desktop session assumptions.

## Android-Specific Adaptations

Android should express the tunnel directly through `VpnService.Builder` and a `sing-box` TUN configuration. The runtime should:

- own the tunnel inside `VpnService`
- expose status via `StateFlow`/callback interfaces to MVI reducers
- keep route and DNS policy in the service layer, not in the UI layer
- make package-based routing a platform concern, not a core-domain concern
- avoid any localhost proxy listener as a debug or fallback mode

The UI should only publish intents such as `Connect`, `Disconnect`, `RefreshSubscription`, and `SelectProfile`. It should not know how packets are forwarded.

## Gradle / Dependency Policy

Use a modular Gradle layout with local or self-hosted dependency resolution first. The external GitLab example
`https://gitlab.services.mts.ru/fc-telecom/mobile/android/gradledepwithoutregistry`
was not accessible from this environment, so the dependency guidance below is a fallback assumption, not a verified copy of that repo.

Fallback policy:

- prefer included builds or locally mirrored Maven artifacts for internal modules
- avoid requiring a public registry for internal dependencies
- keep dependency versions pinned in one root catalog or platform module
- make `:platform:singbox` and any internal MVI/shared libs resolvable offline from checked-out sources

## Testing Stack

Use the Android testing guidance from [android-testing-tools](/Users/alexis/.agents/skills/android-testing-tools/agents/skills/android-testing-tools/SKILL.md):

- Compose or XML screens should have stable test tags
- Page Object wrappers should be used for screen-level flows
- screenshots should be captured at each meaningful state transition
- screenshot output must be visually inspected, not just generated

Recommended test layers:

- unit tests for subscription parsing, profile selection, and render policy
- fake `VpnService`/runtime tests for tunnel state transitions
- `androidTest` UI coverage for connect/disconnect, profile selection, and error states
- screenshot validation for the tunnel home screen and profile setup flow

## What To Verify Next

- confirm the exact `sing-box` Android packaging strategy for this app: embedded binary, shared library, or platform wrapper
- confirm package-based routing requirements for the first release
- confirm whether any `darwin-relux`, `relux-router`, or `swift-testing-tools` concepts have Android analogs that should be mirrored in naming only

## References

- Desktop reusable core: [desktop/internal/vless](/Users/alexis/src/multi-tun/desktop/internal/vless)
- iOS sample baseline for the Relux stack: [relux-sample](/Users/alexis/src/relux-works/relux-sample)
- Relux package: [swift-relux](/Users/alexis/src/relux-works/swift-relux)
- Swift IoC package: [swift-ioc](/Users/alexis/src/relux-works/swift-ioc)
- Android UI testing guidance: [android-testing-tools](/Users/alexis/.agents/skills/android-testing-tools/agents/skills/android-testing-tools/SKILL.md)

