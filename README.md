# vpn-config

`vpn-config` is a repo for the `vless-tun` local Go CLI, replacing the `v2RayTun` client path with a controllable `sing-box` workflow for DenseVPN / DanceVPN subscriptions.

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
vless-tun run
vless-tun reconnect
vless-tun status
vless-tun diagnose
vless-tun stop
vless-tun render
```

Generated artifacts:

- cache snapshot: `~/.cache/vless-tun/snapshot.json` by default
- rendered sing-box config: `~/.config/vless-tun/generated/dancevpn-sing-box.json` by default

## Commands

```bash
vless-tun init
vless-tun refresh
vless-tun list
vless-tun run
vless-tun reconnect
vless-tun status
vless-tun stop
vless-tun render
```

### `vless-tun init`

Creates `~/.config/vless-tun/config.json` by default. Use `--subscription-url` to inject the live DenseVPN key URL without committing it.

### `vless-tun refresh`

Fetches the subscription URL from `~/.config/vless-tun/config.json` by default, detects whether the payload is plaintext or base64, parses all `vless://` profiles, and writes a local cache snapshot.

### `vless-tun list`

Shows the cached profiles in a compact form. Use `--refresh` if you want it to pull the subscription first.

### `vless-tun run`

Renders the selected profile to the configured sing-box JSON and then starts `sing-box` in the background.

Each run creates a new timestamped session log and metadata pair under:

- `~/.cache/vless-tun/sessions/sing-box-session-<UTC timestamp>.log`
- `~/.cache/vless-tun/sessions/session-<UTC timestamp>.json`

The currently active session pointer is stored at:

- `~/.cache/vless-tun/runtime/current-session.json`

`run` is the command that should actually bring the TUN up. `status` does not connect anything by itself.

In `render.mode=system_proxy`, `run` starts a local `mixed` inbound and lets `sing-box` manage macOS system proxy settings instead of creating `utun`.

In `render.mode=tun`, `run` now supports privileged macOS launch backends through `render.privileged_launch`:

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
go build -o vless-tun ./cmd/vpn-config
```

## Notes

- This version manages the local `sing-box` session lifecycle with `run`, `status`, `stop`, and a configurable privileged TUN backend for macOS.
- `reconnect` is the "apply latest config" path: it rereads local config, refreshes the subscription by default, rerenders, and replaces the current session.
- `status` is an introspection view over recorded session state, launch backend, process liveness, interface presence, and cached profile data; it is not a deep traffic verifier.
- If your public IP does not change, check the latest session log first. The expected control flow is `run` -> `status` -> inspect the session log, not `status` alone.
- On macOS the default render mode is still `system_proxy` for low-friction bring-up, but `tun` now works through `render.privileged_launch`.
- Generated config now includes `route.default_domain_resolver`, which `sing-box 1.13.x` expects as part of the DNS resolver migration path.
- Every `run` gets its own timestamped log file so later debugging has a stable artifact even if the next session behaves differently.
- The bypass rule is intentionally domain-suffix based because the original user requirement was `*.ru`. If later you want IP or community rulesets, extend the renderer rather than hardcoding provider-specific blobs.
