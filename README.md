# multi-tun

`multi-tun` currently hosts two local CLIs:

- `vless-tun` for DenseVPN / DanceVPN over `sing-box`
- `openconnect-tun` for Cisco AnyConnect / ASA profile inspection and future OpenConnect runtime work
- `cisco-dump` for manual AnyConnect/CSD capture sessions and local dump artifacts

The `vless-tun` flow replaces the `v2RayTun` client path with a controllable `sing-box` workflow for DenseVPN / DanceVPN subscriptions.

Current scope:

- fetch a live subscription URL such as `https://key.vpn.dance/connect?...`
- decode plaintext or base64 subscription payloads
- parse `vless://` profiles, including Reality + gRPC variants
- cache the latest subscription snapshot locally
- render a `sing-box` config either as a TUN session or as a macOS-friendly system-proxy session, with optional suffix-based direct bypasses

This repo also keeps live notes from previous VPN investigations:

- `v2raytun-dancevpn-routing.md`
- `corp-vpn-wifi-bypass.md`

## Quick Start

```bash
./scripts/setup.sh

# edit ~/.config/vless-tun/config.json and set your subscription_url

vless-tun refresh
vless-tun list
vless-tun start
vless-tun reconnect
vless-tun status
vless-tun diagnose
vless-tun stop
vless-tun render
openconnect-tun status
openconnect-tun profiles
openconnect-tun inspect-profiles
cisco-dump status
```

`./scripts/setup.sh` now also refreshes the repo-local `agents-infra` runtime when `agents-infra` is installed, layers project-specific local instructions into `.agents/.instructions/`, and exposes the repo `vpn-config` skill plus `project-management` in local `.claude/skills` and `.codex/skills`.

Generated artifacts:

- cache snapshot: `~/.cache/vless-tun/snapshot.json` by default
- rendered sing-box config: `~/.config/vless-tun/generated/dancevpn-sing-box.json` by default

## Commands

```bash
vless-tun init
vless-tun refresh
vless-tun list
vless-tun start
vless-tun reconnect
vless-tun status
vless-tun stop
vless-tun render
```

### `openconnect-tun`

Use this companion CLI when you need to inspect Cisco AnyConnect / ASA state, resolve real ASA profile targets, and stage OpenConnect routing experiments next to `vless-tun`.

```bash
openconnect-tun status
openconnect-tun helper status
openconnect-tun helper install
openconnect-tun profiles
openconnect-tun inspect-profiles
openconnect-tun inspect-profiles --dir ~/Downloads/cisco-anyconnect-profiles/profiles
openconnect-tun start --profile 'Ural Outside extended' --mode full --dry-run
openconnect-tun start --profile 'Ural Outside extended' --mode split-include \
  --route 198.51.100.0/24 \
  --route 203.0.113.0/24 \
  --vpn-domains corp.example,digital.example,services.corp.example \
  --dry-run
openconnect-tun reconnect --profile 'Ural Outside extended' --mode full
openconnect-tun routes
openconnect-tun stop

cisco-dump start
cisco-dump status
cisco-dump stop
cisco-dump inspect --session-id 20260326T144914Z
```

Operational notes:

- `openconnect-tun` keeps its own runtime state under `~/.cache/openconnect-tun`, with session logs in `~/.cache/openconnect-tun/sessions` and the current session pointer in `~/.cache/openconnect-tun/runtime/current-session.json`. This is intentionally separate from `~/.cache/vless-tun`.
- `openconnect-tun helper install` performs the one-time privileged setup for autonomous runs. It installs a root LaunchDaemon that exposes a user-owned unix socket, so later `start` / `reconnect` / `stop` prefer the helper automatically and only fall back to `sudo` when the helper is absent.
- `--profile` resolves against local AnyConnect XML `HostEntry` values and automatically deduplicates the same server repeated across `/opt/cisco/...` and `~/Downloads/...`.
- the canonical lifecycle commands are now `start`, `reconnect`, `status`, and `stop`; `run`, `connect`, and `disconnect` remain as compatibility aliases.
- `openconnect-tun` can read auth defaults from `~/.config/openconnect-tun/config.json`. Current Corp bootstrap convention is fully keychain-backed: `auth.username_keychain_account=corp-vpn/username` and `auth.password_keychain_account=corp-vpn/password`. Plain `auth.username` remains as a compatibility fallback. `totp_secret_keychain_account` stays optional and is intentionally not wired by default.
- live auth now defaults to `--auth aggregate`, which is the only path that currently completes Corp SSO+CSD on this machine; `--auth openconnect` remains available as the direct `openconnect --authenticate` path for debugging. `vpn-auth` is used for the browser-assisted SAML steps in aggregate mode, with preset-cookie support for follow-up pages.
- the CSD helper is resolved from the active OpenConnect install, preferring native Cisco `libcsd.dylib` when it is available under `~/.cisco/...`; otherwise it falls back to Homebrew's stable `opt/openconnect/libexec/openconnect/csd-post.sh` path instead of versioned `Cellar/...` paths. The fallback `csd-post.sh` path is still wrapped with tiny macOS shims for `pidof` and GNU-style `stat -c %Y`.
- `cisco-dump` keeps its own runtime state under `~/.cache/cisco-dump`, with session logs in `~/.cache/cisco-dump/sessions`, the current session pointer in `~/.cache/cisco-dump/runtime/current-session.json`, mirrored Cisco logs and cache artifacts under each session directory, tracked Cisco per-pid `lsof` snapshots, all-loopback TCP snapshots from `lsof`/`netstat`, and optional localhost loopback pcaps via `tcpdump`.
- when a `cisco-dump` session stops with a loopback pcap present, it now also derives `ocsc-timeline.txt` and `ocsc-summary.txt` from AnyConnect OCSC loopback traffic. `cisco-dump inspect --session-id ...` can re-run that decoder on an older captured session.
- live `start` now emits compact `auth_stage:` updates in the terminal during authentication instead of forcing you to tail the session log for every auth transition. The full detailed auth log still stays in the session log file.
- live `start` now resolves the privileged backend automatically: helper first when `openconnect-tun helper install` has been completed, otherwise the old `sudo -v` + `sudo -n` path so the privileged password prompt still does not compete with the cookie being piped into `--cookie-on-stdin`.
- `--mode full` uses the stock `vpnc-script`, so OpenConnect will own default route and global DNS. Treat it as a smoke-test path, not a coexistence-safe mode.
- `--mode split-include` uses `vpn-slice`. On macOS that means scoped `/etc/resolver/<domain>` files for VPN DNS instead of replacing the global resolver stack, which is the direction we want for Corp coexistence next to `vless-tun`.

Example `openconnect-tun` config:

```json
{
  "cache_dir": "~/.cache/openconnect-tun",
  "default_profile": "Ural Outside extended",
  "default_mode": "split-include",
  "split_include": {
    "routes": [
      "10.0.0.0/8",
      "11.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ],
    "nameservers": [
      "10.23.16.4",
      "10.23.0.23"
    ],
    "vpn_domains": [
      "corp.example"
    ]
  },
  "auth": {
    "username_keychain_account": "corp-vpn/username",
    "password_keychain_account": "corp-vpn/password"
  }
}
```

`split_include.vpn_domains` accepts a list of suffix masks. `corp.example` covers `*.corp.example`; for known Corp `/outside` profiles `openconnect-tun` also augments split DNS with the extra official Cisco suffix set (`inside.corp.example`, `region.corp.example`, `branch.example`, `workspace.example`, and related domains) so the config can stay minimal. `split_include.nameservers` lets you force the scoped resolver IPs when the ASA/OpenConnect environment only yields incomplete DNS like `10.96.60.x`.

### `vless-tun init`

Creates `~/.config/vless-tun/config.json` by default. Use `--subscription-url` to inject the live DenseVPN key URL without committing it.

### `vless-tun refresh`

Fetches the subscription URL from `~/.config/vless-tun/config.json` by default, detects whether the payload is plaintext or base64, parses all `vless://` profiles, and writes a local cache snapshot.

### `vless-tun list`

Shows the cached profiles in a compact form. Use `--refresh` if you want it to pull the subscription first.

### `vless-tun start`

Renders the selected profile to the configured sing-box JSON and then starts `sing-box` in the background.

Each start creates a new timestamped session log and metadata pair under:

- `~/.cache/vless-tun/sessions/sing-box-session-<UTC timestamp>.log`
- `~/.cache/vless-tun/sessions/session-<UTC timestamp>.json`

The currently active session pointer is stored at:

- `~/.cache/vless-tun/runtime/current-session.json`

`start` is the command that should actually bring the TUN up. `status` does not connect anything by itself.

In `render.mode=system_proxy`, `start` starts a local `mixed` inbound and lets `sing-box` manage macOS system proxy settings instead of creating `utun`.

In `render.mode=tun`, `start` now supports privileged macOS launch backends through `render.privileged_launch`:

- `auto`: resolve to `sudo` for TUN as a regular user and `direct` when already root
- `sudo`: run `sudo sing-box run -c ...` after caching credentials with `sudo -v`
- `direct`: run `sing-box` directly; intended for already-root environments
- `launchd`: install/update a system LaunchDaemon and manage the TUN session through `launchctl`

### `vless-tun reconnect`

Reloads the local config, refreshes the subscription cache by default, rerenders the selected profile, stops any currently recorded session, and starts a fresh `sing-box` session.

This is the command to use after changing:

- `selected_profile`
- `render.mode`
- `render.bypass_suffixes`
- any other render-time setting in `~/.config/vless-tun/config.json`

### `vless-tun status`

Shows the current local view of the tunnel state:

- whether a recorded `sing-box` session is active, stale, or absent
- the current session ID, PID, launch mode, start timestamp, and log file path
- whether the configured TUN interface exists, or which proxy listener is active in `system_proxy` mode
- whether the rendered config file exists
- which profile is selected from cache
- which bypass suffixes are configured
- which cached profiles are available

This is a heuristic runtime status, not a control plane.

### `vless-tun diagnose`

Prints a focused runtime diagnostic view for the current launch backend. When `render.privileged_launch.mode=launchd`, it checks the configured LaunchDaemon label and reports the current `launchd` state and PID without requiring you to remember the raw `launchctl print ...` command.

### `vless-tun stop`

Stops the currently recorded `sing-box` session using `SIGTERM` by default. Use `--force` if you want it to escalate to `SIGKILL` after the timeout.

### `vless-tun render`

Selects a cached profile and writes a sing-box JSON config with:

- either a TUN inbound or a `mixed` inbound with `set_system_proxy`
- proxy detour for the rest of the traffic
- optional direct DNS and direct outbound for configured suffix bypasses

If `render.bypass_suffixes` is empty, the renderer produces a simple full-tunnel config with no suffix-based bypasses.

If `render.mode=system_proxy`, the renderer produces a non-TUN config intended for macOS bring-up without root or Network Extension privileges.

## Local Config

Default live config path:

- `~/.config/vless-tun/config.json`

Repo-local example:

- `configs/local.example.json`

If you want to keep using a repo-local config, pass `--config`.

Important fields:

- `subscription_url`: live DenseVPN / DanceVPN subscription URL
- `selected_profile`: optional selector by exact id, exact name, or substring
- `cache_dir`: where refresh snapshots are stored
- `render.mode`: `system_proxy` or `tun`
- `render.output_path`: target sing-box config path
- `render.proxy_listen_address`: local listen address for `system_proxy` mode
- `render.proxy_listen_port`: local listen port for `system_proxy` mode
- `render.interface_name`: TUN interface name for `tun` mode
- `render.tun_addresses`: TUN addresses for `tun` mode
- `render.privileged_launch.mode`: `auto`, `sudo`, `direct`, or `launchd`
- `render.privileged_launch.label`: LaunchDaemon label used when `mode=launchd`
- `render.privileged_launch.plist_path`: plist destination used when `mode=launchd`
- `render.bypass_suffixes`: domains that should go `direct`; set `[]` for full-tunnel bring-up
- `render.proxy_dns`: upstream DNS endpoint for proxied traffic

### Full TUN on macOS

Example config fragment for a real TUN session managed by `launchd`:

```json
{
  "render": {
    "mode": "tun",
    "privileged_launch": {
      "mode": "launchd",
      "label": "works.relux.vless-tun",
      "plist_path": "/Library/LaunchDaemons/works.relux.vless-tun.plist"
    }
  }
}
```

Then run:

```bash
vless-tun reconnect --refresh
vless-tun status
```

## Development

```bash
go fmt ./...
go test ./...
go build -o vless-tun ./cmd/vless-tun
go build -o openconnect-tun ./cmd/openconnect-tun
go build -o cisco-dump ./cmd/cisco-dump
```

## Notes

- This version manages the local `sing-box` session lifecycle with `start`, `status`, `stop`, and a configurable privileged TUN backend for macOS.
- `reconnect` is the "apply latest config" path: it rereads local config, refreshes the subscription by default, rerenders, and replaces the current session.
- `status` is an introspection view over recorded session state, launch backend, process liveness, interface presence, and cached profile data; it is not a deep traffic verifier.
- If your public IP does not change, check the latest session log first. The expected control flow is `start` -> `status` -> inspect the session log, not `status` alone.
- On macOS the default render mode is still `system_proxy` for low-friction bring-up, but `tun` now works through `render.privileged_launch`.
- Generated config now includes `route.default_domain_resolver`, which `sing-box 1.13.x` expects as part of the DNS resolver migration path.
- Every `start` gets its own timestamped log file so later debugging has a stable artifact even if the next session behaves differently.
- The bypass rule is intentionally domain-suffix based because the original user requirement was `*.ru`. If later you want IP or community rulesets, extend the renderer rather than hardcoding provider-specific blobs.
