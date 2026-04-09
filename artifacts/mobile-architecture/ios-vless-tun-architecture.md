# iOS VLESS TUN Architecture Memo

Board chain: `TASK-260408-2gyzok` -> `STORY-260408-2yaz1i` -> `EPIC-260408-1lxv8d`

## Decision

An iOS `vless-tun` client can be built as a TUN-only design around `NetworkExtension` and `sing-box-for-apple`. The right shape is:

- a SwiftUI host app for onboarding, settings, subscription import, profile selection, and tunnel control
- a `PacketTunnelProvider` extension for the actual tunnel runtime
- a shared core package for subscription parsing, profile selection, routing policy, and sing-box config rendering

This should stay TUN-only. No local SOCKS, mixed, or HTTP listeners on loopback.

> Localhost listeners are forbidden here. The extension must talk to the tunnel runtime directly through the packet tunnel path, not through `127.0.0.1` or `::1`.

## What I Reviewed

Local refs:

- [relux-sample App.swift](/Users/alexis/src/relux-works/relux-sample/relux_sample/App.swift)
- [relux-sample IoC.swift](/Users/alexis/src/relux-works/relux-sample/relux_sample/IoC/IoC.swift)
- [relux-sample Auth module](/Users/alexis/src/relux-works/relux-sample/Packages/Auth/Sources/AuthReluxImpl/Auth+Module.swift)
- [relux-sample Auth package](/Users/alexis/src/relux-works/relux-sample/Packages/Auth/Package.swift)
- [relux-sample AuthUI package](/Users/alexis/src/relux-works/relux-sample/Packages/AuthUI/Package.swift)
- [relux-sample TestInfrastructure package](/Users/alexis/src/relux-works/relux-sample/Packages/TestInfrastructure/Package.swift)
- [swift-relux Package.swift](/Users/alexis/src/relux-works/swift-relux/Package.swift)
- [swift-ioc Package.swift](/Users/alexis/src/relux-works/swift-ioc/Package.swift)
- [swiftui-reluxrouter Package.swift](/Users/alexis/src/relux-works/swiftui-reluxrouter/Package.swift)

Public refs:

- [sing-box for Apple platforms](https://sing-box.sagernet.org/clients/apple/)
- [sing-box Apple features](https://sing-box.sagernet.org/zh/clients/apple/features/)
- [sing-box-for-apple GitHub](https://github.com/SagerNet/sing-box-for-apple)
- [Apple Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
- [Apple Network Extension](https://developer.apple.com/documentation/NetworkExtension)

## Recommended Module Graph

Use a split that mirrors the `relux-sample` pattern: root app plus feature packages, with shared state and UI boundaries.

```text
iOS App Host
  -> App shell / settings / subscription import / tunnel control
  -> Relux root, IoC bootstrap, navigation router
  -> App Group storage and NETunnelProviderManager control

PacketTunnelProvider extension
  -> tunnel bootstrap only
  -> sing-box runtime integration
  -> packet flow bridge
  -> DNS / route config application

Shared core packages
  -> subscription fetch and decode
  -> profile model and selection
  -> routing policy and bypass rules
  -> sing-box config render
  -> validation and persistence helpers
```

Concrete package split for the iOS side:

- `VlessModels`
- `VlessCore`
- `VlessReluxInt`
- `VlessReluxImpl`
- `VlessUIAPI`
- `VlessUI`
- `VlessTunnelRuntime`

That split is intentionally close to the `Auth` / `AuthUI` / `TestInfrastructure` pattern in `relux-sample`.

## Host App vs PacketTunnelProvider

The host app should own everything user-facing:

- subscription onboarding
- profile selection
- tunnel start/stop buttons
- status and diagnostics UI
- secure storage and app-group state
- navigation through `ReluxRouter` or a `swiftui-reluxrouter` equivalent

The `PacketTunnelProvider` extension should stay narrow:

- load or receive the rendered sing-box config
- start the tunnel runtime
- read packet flow and write packets back
- report status to the host app

Do not move UI or navigation logic into the extension. The extension should be treated as a runtime adapter, not as a second app.

## Reusable multi-tun Core Pieces

The pieces from `multi-tun` that should be reused conceptually are:

- subscription fetch and decode
- profile parsing and normalization
- transport validation
- routing policy and bypass suffix logic
- sing-box JSON synthesis
- config validation

The pieces that should not be ported as-is are the macOS process/session primitives:

- launchd orchestration
- `sudo` / privileged helper flow
- system DNS handoff
- nested tunnel checks against macOS interfaces

In practice, the iOS core should be pure Swift and platform-neutral where possible. The platform adapter should only begin at the point where the packet tunnel needs to be started or reconfigured.

## Apple-Specific Adaptations

The iOS version should adapt the current `vless-tun` design to Apple semantics:

- rely on `NetworkExtension` packet tunnel semantics instead of macOS process supervision
- use App Group storage for shared config/state between app and extension
- apply route and DNS settings through packet tunnel network settings, not system proxy plumbing
- keep the TUN interface managed by Darwin, not hardcoded as a macOS-style stable interface name
- preserve the TUN-only policy and do not add loopback proxy endpoints

The `sing-box-for-apple` repo is the right signal that this shape is intended and supported. It is an experimental Apple client, but it matches the architecture we want much more closely than a localhost proxy design.

## Relux / Tuist Guidance

The local `relux-sample` repo shows a useful pattern:

- `App.swift` owns the root `Relux.Resolver`
- `IoC.swift` registers the graph and wires modules together
- feature modules are isolated behind package boundaries
- UI is split from relux/business logic

For iOS `vless-tun`, use the same shape:

- root app target with Tuist
- a clean `IoC` bootstrap layer
- feature packages for settings, subscription import, tunnel status, and diagnostics
- a shared tunnel core package used by both host app and extension

Dependency guidance based on the sample:

- `swift-relux` is the state-management backbone
- `swift-ioc` is the resolver/container layer
- `swiftui-relux` is the SwiftUI bridge
- `swiftui-reluxrouter` exports `ReluxRouter` and is the navigation layer I found locally

I did not find a standalone `darwin-relux` repo in the local workspace. I infer that name refers to the Darwin-specific runtime/support layer for app or extension plumbing, but that still needs explicit verification before implementation.

I also did not find a standalone `relux-router` repo. I did find `swiftui-reluxrouter`, which exports `ReluxRouter`, so that is the likely package you meant.

The local `relux-sample` package manifests also show the dependency style to mirror:

- `Auth` uses `swift-ioc` and `swift-relux`
- `AuthUI` depends on `Auth` plus `swiftui-relux`
- `TestInfrastructure` depends on `swift-relux`

That is a good template for `vless-tun` packages and for the tunnel extension boundary.

## Testing Stack

For validation, use:

- `ios-testing-tools` for UI and screenshot validation
- unit tests for pure core parsing/rendering
- integration tests for app-group state and provider startup
- device-level smoke tests for the packet tunnel path

The `swift-testing-tools` repo was not present locally, so I could not inspect it directly. Treat it as an unverified optional dependency until the exact package name and role are confirmed. For now, `ios-testing-tools` is the concrete workflow baseline.

Use `ios-app-manager` if this becomes a Tuist-scaffolded project. The useful setup sequence is:

- `init`
- `ioc setup`
- `relux setup`
- `secure-store setup`
- `utilities setup`
- `foundation-plus setup`
- `swiftui-plus setup`
- `app-extensions setup`

## Open Questions

- Confirm whether `darwin-relux` is a separate repo or just the Darwin support layer inside another package.
- Confirm whether the router package should be consumed as `ReluxRouter` from `swiftui-reluxrouter`.
- Confirm whether `sing-box-for-apple` is being embedded as source, vendored as a dependency, or treated as the upstream implementation target.
- Confirm the minimum iOS version; the sample packages are iOS 17+, but the tunnel baseline may support lower.

## Bottom Line

The iOS port is viable and should be clean if it follows the same discipline as the desktop refactor:

- TUN only
- shared pure core
- thin platform adapter
- no localhost proxy listeners
- Relux for app state and navigation, not for tunnel plumbing

That is the architecture to implement for `TASK-260408-2gyzok`.
