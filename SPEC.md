# multi-tun Specification

## Problem

`v2RayTun` accepts the DanceVPN subscription and connects successfully, but the local `Routing` feature was not enough to produce a real `.ru` bypass on this Mac. The replacement path needs to keep the subscription convenience while moving tunnel behavior into a controllable stack.

At the same time, the repo now also needs a companion `openconnect-tun` CLI for Cisco AnyConnect / ASA profile inspection so corporate split-routing and bypass planning can live next to the VLESS flow instead of in scattered shell scripts and old experiments.

## Primary Goal

Build local CLIs and agent guidance that can:

1. manage a live DenseVPN subscription URL
2. refresh and parse `vless://` profiles from that URL
3. render a `sing-box` client config either as a simple full tunnel or a deterministic `.ru` bypass
4. inspect Cisco AnyConnect / ASA profile metadata and CLI-visible profile lists for future OpenConnect automation
5. fit the usual skill-style repo layout with board, setup script, docs, and agent guidance

## Users

- the repo owner operating DenseVPN locally
- future agents working inside this repo

## Functional Requirements

### Subscription Handling

- Load a live subscription URL from gitignored local config.
- Allow lifecycle commands to override `current.server` and `current.profile` with positional `server [profile]` arguments while keeping `~/.config/vless-tun/config.json` as the no-argument default.
- Allow `openconnect-tun start|reconnect` to override `default.server_url` and `default.profile` with positional `server [profile]` arguments while keeping `~/.config/openconnect-tun/config.json` as the no-argument default.
- Allow configured OpenConnect server/profile aliases, where `servers.<alias>.server_url` is the real ASA endpoint and `servers.<alias>.profiles.<profile_alias>.name` is the real AnyConnect profile label.
- Support plaintext payloads and base64 payloads.
- Parse one or more `vless://` URIs.
- Inspect subscription URLs through a safe analyzer chain that reports fetch/parse attempts without printing raw VLESS URIs or sensitive key material.
- Keep a local cache snapshot to avoid reparsing by hand.

### Profile Model

- Extract profile name, host, port, UUID, network type, TLS/Reality settings, and transport details.
- Select an active configured server/profile through `current.server` and `current.profile`, with CLI overrides for `--server`, `--profile`, and direct subscription `--selector`.
- Keep remote VLESS profiles in the refresh cache; config profile entries are local aliases/selectors plus routing policy, not copied subscription payloads.

### sing-box Rendering

- Produce JSON config compatible with the current sing-box docs.
- Generate a TUN inbound.
- Generate a proxy outbound from the parsed VLESS profile.
- Generate `direct` and `block` outbounds.
- Enable DNS hijack.
- Support direct route CIDRs from `routing.routes`.
- In TUN mode, exclude IP-literal upstream VLESS endpoints from generated TUN routes and route those endpoint CIDRs `direct`, preventing broad full-tunnel routes from capturing the tunnel's own server traffic.
- When a VLESS TUN session is layered above active OpenConnect split DNS, keep the public resolver handoff scoped to the VLESS TUN interface without copying corporate split domains into macOS search suffixes.
- Support two rendering modes:
  - full tunnel when no bypass suffixes are configured
  - split DNS/direct routing when suffix bypasses are configured
    - `.ru` and `.xn--p1ai` use direct DNS and direct outbound
    - everything else uses proxy DNS and proxy outbound
- Support `tun` as the only transport style.
- For `tun` mode on macOS, support privileged launch strategies:
  - `sudo` / direct process execution
  - shared `vpn-core` daemon management for persistent real-TUN sessions

### CLI

- `setup`: scaffold `~/.config/vless-tun/config.json` by default using the preferred config schema
- `init`: create `~/.config/vless-tun/config.json` by default
- `refresh`: fetch and cache subscription
- `list`: inspect cached profiles for the selected configured server
- `set-current`: persist `current.server` and `current.profile`; profile may be omitted when the selected server has a `default` profile or exactly one profile
- `run`: start `sing-box` in the background from the rendered config and persist session metadata; provider/profile shortcuts such as `start dance`, `start freedom`, and `start fortinetz nl` override the default config selection
- `reconnect`: refresh local state, stop recorded `sing-box` sessions across configured server cache directories, and start the selected profile in one command
- `status`: show local runtime state, launch backend, cached selection, and configured bypasses
- `diagnose`: inspect tunnel/runtime state without requiring provider/profile selection; `diagnose config` validates config selection separately
- `stop`: stop the recorded `sing-box` session without requiring provider/profile selection
- `render`: emit sing-box config
- in `network.mode=tun` on macOS, startup must reject nested-tunnel bring-up when the upstream VLESS server route already points at another VPN interface (`utun*`, `tun*`, `ppp*`, `ipsec*`)
- `openconnect-tun setup`: scaffold `~/.config/openconnect-tun/config.json` plus placeholder keychain entries from one user-facing VPN profile name
- `openconnect-tun status`: inspect AnyConnect CLI state and active connection metadata
- `openconnect-tun profiles`: list ASA profiles surfaced by `vpn hosts`
- `openconnect-tun inspect-profiles`: parse local AnyConnect XML profiles and expose server entries plus bypass-relevant flags
- `openconnect-tun set-current`: persist `default.server_url` and `default.profile`; profile may be omitted when the selected configured server has the current default profile or exactly one configured profile; server/profile inputs may be friendly aliases
- `openconnect-tun run`: authenticate with aggregate-auth or `openconnect --authenticate`, optionally using `vpn-auth` only as the external-browser automation helper, then start OpenConnect in either `full` or `split-include` mode; `start msk msk-outside` and `reconnect ural ural-outside` override the default config selection for one run while passing the configured real server URL/profile label to OpenConnect
- `openconnect-tun` config may define `servers.<url>.auth.second_factor.mode` as `manual_otp` or `totp_auto`, with `--second-factor-mode` as a per-run override for SAML flows whose second factor changes between SMS/manual OTP and authenticator TOTP
- `openconnect-tun` config may define `servers.<url>.auth.fallback_servers` for endpoint-specific aggregate-auth fallback targets when a balancer backend returns an auth-request without `sso-v2-login`
- `openconnect-tun` config may define `servers.<url>.client_mimicry` for endpoint-specific AnyConnect identity: user-agent, version, OS/device-id, local hostname, aggregate-auth capabilities, and aggregate-auth HTTP headers
- `openconnect-tun reconnect`: replace the active OpenConnect session in one command
- `vpn-core install|status|uninstall`: manage the shared privileged daemon used for passwordless post-SSO connect/stop flows and privileged `sing-box` TUN lifecycle
- `vpn-core inspect-vless-url`: run a user-space VLESS URL metadata probe through a fixed analyzer chain
- `openconnect-tun helper install|status|uninstall`: compatibility wrapper around `vpn-core`
- `openconnect-tun routes`: inspect routes currently attached to the live OpenConnect utun interface
- `openconnect-tun stop`: stop the active OpenConnect process cleanly
- `dump start|status|stop|inspect`: canonical packet-dump workflow for tunnel-aware VPN diagnostics; `cisco-dump` remains as a compatibility alias
- `scripts/setup.sh`: install the shipped toolchain end-to-end, including `sing-box` for VLESS runtime plus `vpn-auth` and its TOTP prerequisite path for aggregate OpenConnect auth; on macOS it should default to host-native Apple Silicon vs Intel builds and allow explicit `--mac-arch arm64|amd64` artifact-only cross-builds

## Non-Goals For This Iteration

- GUI automation
- provider-specific hacks outside standard VLESS / Reality / gRPC parsing
- remote rule-set downloads

## Constraints

- Keep secrets out of committed files.
- Keep tests offline.
- Prefer standard library over extra dependencies.
- Keep generated config self-contained enough for fast inspection.
- Do not let OpenConnect full-tunnel experiments silently clobber the resolver state needed by an already active `vless-tun`; scoped corporate DNS is required for the steady-state design.

## Deliverables

- Go CLI
- tests and fixtures
- setup script
- platform roots for `desktop/`, `android/`, and `ios/`, with desktop code organized into `core`, `vless`, and `anyconnect`
- Android release helpers must produce a signed Play bundle together with colocated `release-notes.txt` and `native-debug-symbols.zip` sidecars
