# Why `vless-tun` Stays TUN-Only

Updated: 2026-04-08

This note documents a concrete macOS case study from `v2RayTun` and explains why this repository now treats direct TUN as the only supported path for `vless-tun`.

Related material:

- [Desktop audit of `v2RayTun` Apple runtime](../v2raytun-apple-audit/README.md)
- [Broader VLESS tunnel protection note](../vless-tunnel-protection/README.md)

## Executive Summary

The core lesson is simple:

- a localhost proxy inside a consumer VPN client is a same-device attack surface
- if another local process can connect to that proxy without strong authentication, it can use the tunnel or inspect tunnel behavior
- if the platform supports direct TUN, the cleaner design is to avoid the localhost proxy layer entirely

This repository previously had an optional `system_proxy` path. That mode has been removed. `vless-tun` is now TUN-only by design.

## What We Found In `v2RayTun` On macOS

The `v2RayTun` macOS app bundle ships as a native Apple Network Extension client, but the runtime path is not a pure packet-tunnel-to-remote design.

The local audit found:

- saved runtime config with a local SOCKS inbound on `[::1]:1080`
- a tun-to-SOCKS bridge config pointing tunnel traffic at `::1:1080`
- repeated startup logs showing `Primary inbound (DEFAULT) -> ::1:1080` and `Starting SOCKS5 tunnel on ::1:1080…`
- live proof that a separate shell process could connect to the active listener without credentials

The live proof was direct:

- raw SOCKS5 greeting returned `0500`, which means `NO AUTHENTICATION REQUIRED`
- `curl --socks5-hostname '[::1]:1080' ...` completed successfully through the active tunnel

The detailed evidence is captured in the audit note:

- [Desktop audit of `v2RayTun` Apple runtime](../v2raytun-apple-audit/README.md)

## Why This Design Is Weak

This is not about whether the proxy listens on `127.0.0.1` or `[::1]`. The problem is architectural:

- the VPN client creates a privileged local network entry point
- another local process can try to use that entry point
- the client is now relying on localhost as if it were a trust boundary

That is a bad assumption for end-user machines.

Once an unauthenticated local SOCKS listener exists, a second process may be able to:

- learn that the VPN session is active
- use the tunnel as an egress path
- observe the tunnel exit IP
- piggyback on the tunnel for arbitrary outbound traffic

This note does not claim that every localhost proxy automatically exposes full Xray management APIs. In the `v2RayTun` macOS audit, the saved runtime config did not show Xray `HandlerService` enabled. The point is narrower and still serious: plain unauthenticated localhost SOCKS is already enough to create avoidable same-device exposure.

## Why `vless-tun` Is The Better Path

`vless-tun` now enforces a much simpler model:

- `network.mode=tun` is the only accepted mode
- config validation rejects anything else
- the renderer emits only a `tun` inbound
- no local `socks`, `mixed`, `http`, or Xray API listener is rendered in the supported path

Repository evidence:

- default config path uses `network.mode=tun` in [internal/config/config.go](../../internal/config/config.go)
- validation rejects non-TUN modes in [internal/config/config.go](../../internal/config/config.go)
- inbound rendering is TUN-only in [internal/singbox/render.go](../../internal/singbox/render.go)
- the repo documents removal of `system_proxy` in [README.md](../../README.md)

The important difference is not branding. It is surface area:

- `v2RayTun` macOS: active localhost proxy surface exists during a tunnel session
- `vless-tun`: supported path does not create that surface

That does not make `vless-tun` magically invisible to all local observation. In a full-device tunnel, another local process can still make its own outbound request and discover the tunnel's egress behavior. But that is fundamentally different from handing local processes an explicit proxy endpoint.

## Design Rule

For consumer VPN clients, the default rule should be:

- if direct TUN is possible, do direct TUN
- do not insert a localhost proxy hop unless there is a hard platform constraint
- if a local proxy is unavoidable, treat localhost as hostile and require strong per-session access control

This repository follows that rule now.

## Scope And Limits

This note is a macOS case study. It does not prove that the iOS build of `v2RayTun` behaves identically.

What it does prove is still useful:

- the Apple implementation family behind `v2RayTun` is not inherently protected from localhost-proxy design mistakes just because it uses packet-tunnel extensions
- the safer design choice for this repository was to remove `system_proxy` and keep `vless-tun` TUN-only
