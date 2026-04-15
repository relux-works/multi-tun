# multi-tun

`multi-tun` currently hosts local CLIs for:

- `vless-tun` for DenseVPN / DanceVPN over `sing-box`
- `openconnect-tun` for Cisco AnyConnect / ASA profile inspection and future OpenConnect runtime work
- `dump` for manual VPN capture sessions and local dump artifacts

The `vless-tun` flow replaces the `v2RayTun` client path with a controllable `sing-box` workflow for DenseVPN / DanceVPN subscriptions.

Current scope:

- fetch a live subscription URL such as `https://key.vpn.dance/connect?...`
- decode plaintext or base64 subscription payloads
- parse `vless://` profiles, including Reality + gRPC variants
- cache the latest subscription snapshot locally
- render a `sing-box` TUN config with optional suffix-based direct bypasses

This repo also keeps live notes from previous VPN investigations:

- `v2raytun-dancevpn-routing.md`
- `corp-vpn-wifi-bypass.md`

Operational instructions live under [`instructions/`](instructions/README.md):

- [`instructions/docker-desktop-private-registry.md`](instructions/docker-desktop-private-registry.md)
- [`instructions/colima-private-registry.md`](instructions/colima-private-registry.md)

## Platform Layout

- `desktop/`: current shipped codebase
  - `desktop/internal/core/`: shared desktop infrastructure
  - `desktop/internal/vless/`: VLESS-specific desktop logic
  - `desktop/internal/anyconnect/`: Cisco/OpenConnect-specific desktop logic
- `android/`: Android client/runtime workspace with a modular app shell, persisted generic tunnel config, real `VpnService` + `libbox` TUN runtime, and a separate observer app for cross-UID egress checks
- `ios/`: future iOS client/runtime workspace

Android real-device smoke currently lives behind the dedicated runner:

```bash
./scripts/android/run-device-smoke.sh
./scripts/android/run-device-smoke.sh --serial 535a1632
./scripts/android/run-device-smoke.sh \
  --serial 535a1632 \
  --test-class works.relux.vless_tun_app.TunnelHomeEditorStateTest
./scripts/android/run-device-smoke.sh \
  --serial 535a1632 \
  --test-class works.relux.vless_tun_app.TunnelEgressSmokeTest \
  --source-inline-vless-from-desktop-config
./scripts/android/run-device-suite.sh \
  --serial 535a1632 \
  --source-inline-vless-from-desktop-config
```

That path uses preinstall + direct `adb shell am instrument` instead of `connectedDebugAndroidTest`, which is more reliable on MIUI/Xiaomi devices.
The stable split is:

- `TunnelHomeSmokeTest#tunnelHomeLoads` for cold app launch via `UiAutomator`
- `TunnelHomeEditorStateTest` for source-url editor/save regression via Compose instrumentation
- `TunnelConnectSmokeTest` for `VpnService`/TUN bring-up
- `TunnelEgressSmokeTest` for real cross-UID egress change through the observer app

The live egress loop is verified on a real Xiaomi device with a separate observer app: direct observer egress was `91.77.167.22 · Russia (RU)`, and after connect it switched to `144.31.90.46 · Finland (FI)`.

## Quick Start

```bash
./scripts/setup.sh
./scripts/setup.sh --mac-arch amd64
./scripts/deinit.sh --dry-run

# edit ~/.config/vless-tun/config.json and set source.url

vless-tun refresh
vless-tun list
vless-tun setup --source-url "vless://..."
vless-tun start
vless-tun reconnect
vless-tun status
vless-tun diagnose
vless-tun stop
vless-tun render
openconnect-tun status
openconnect-tun setup --vpn-name "Corp VPN"
openconnect-tun profiles
openconnect-tun inspect-profiles
dump status
```

`./scripts/setup.sh` installs the shipped desktop toolchain end-to-end: it ensures the runtime prerequisites such as `sing-box`, builds the bundled `desktop/cmd/vpn-auth` Swift helper, and links the resulting binaries into `~/.local/bin`.

That installed toolchain now also includes `android-release`, the local Go helper for:

- seeding Android release-signing metadata
- generating the Play upload keystore
- building a signed `app-release.aab` for Play test tracks with required release notes sidecar output
- emitting `native-debug-symbols.zip` and ProGuard mapping artifacts for Play symbolication
- manually publishing the signed bundle to a chosen Google Play track via Gradle Play Publisher

On macOS the default `./scripts/setup.sh` path is host-native: on Apple Silicon it builds/install `arm64` binaries, and on Intel Macs it builds/install `amd64` binaries with the normal toolchain prerequisites for that machine. If you explicitly pass `--mac-arch arm64|amd64` for the non-host architecture, setup switches into artifact-only cross-build mode and writes desktop binaries into `artifacts/releases/` without touching `~/.local/bin`, configs, or skill wiring.

`./scripts/deinit.sh` removes the managed `multi-tun` global/local skill links and `~/.local/bin` symlinks. Config, cache, keychain secrets, and repo build artifacts stay intact unless you pass the explicit `--purge-*` flags.

Generated artifacts:

- cache snapshot: `~/.cache/vless-tun/snapshot.json` by default
- rendered sing-box config: `~/.config/vless-tun/generated/sing-box.json` by default

## Commands

```bash
vless-tun setup
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

The corporate hostnames, domains, profile labels, and IPs shown in the examples below are anonymized placeholders.

```bash
vpn-core status
vpn-core install
openconnect-tun status
openconnect-tun helper status
openconnect-tun helper install
openconnect-tun profiles
openconnect-tun inspect-profiles
openconnect-tun inspect-profiles --dir ~/Downloads/cisco-anyconnect-profiles/profiles
openconnect-tun setup --vpn-name 'Corp VPN'
openconnect-tun start --profile 'Ural Outside extended' --mode full --dry-run
openconnect-tun start --profile 'Ural Outside extended' --mode split-include \
  --route 198.51.100.0/24 \
  --route 203.0.113.0/24 \
  --vpn-domains corp.example,digital.example,services.corp.example \
  --bypass-suffixes bypass.corp.example \
  --dry-run
openconnect-tun reconnect --profile 'Ural Outside extended' --mode full
openconnect-tun routes
openconnect-tun stop

dump start
dump start --probe-host gitlab.services.corp.example --probe-host portal.corp.example
dump status
dump stop
dump inspect --session-id 20260326T144914Z
```

Operational notes:

- `openconnect-tun` keeps its own runtime state under `~/.cache/openconnect-tun`, with session logs in `~/.cache/openconnect-tun/sessions` and the current session pointer in `~/.cache/openconnect-tun/runtime/current-session.json`. This is intentionally separate from `~/.cache/vless-tun`.
- `vpn-core install` performs the one-time privileged setup for autonomous runs. It installs a shared root LaunchDaemon that exposes a user-owned unix socket, so later `openconnect-tun` and `vless-tun` commands can reuse the same trusted backend without repeated `sudo`.
- on macOS `vless-tun start` in `network.mode=tun` now refuses to start if the upstream VLESS server itself already routes through another VPN interface such as `utun*`, `tun*`, `ppp*`, or `ipsec*`. That avoids accidental nested-tunnel startup where `vless-tun` silently builds on top of `v2RayTun`, AnyConnect, or another active VPN and drags the whole network into an undefined state.
- Existing installs of the legacy `works.relux.openconnect-tun-helper` daemon are auto-detected for compatibility. A fresh `vpn-core install` replaces that legacy helper with the shared core service.
- `openconnect-tun helper install|status|uninstall` remain as compatibility wrappers around the shared `vpn-core` service.
- `--profile` resolves against local AnyConnect XML `HostEntry` values and automatically deduplicates the same server repeated across `/opt/cisco/...` and `~/Downloads/...`.
- the canonical lifecycle commands are now `start`, `reconnect`, `status`, and `stop`; `run`, `connect`, and `disconnect` remain as compatibility aliases.
- `openconnect-tun` can read auth defaults from `~/.config/openconnect-tun/config.json`. The preferred shape is `servers.<url>.auth`, so credentials are selected from the server being used. The legacy root-level `auth` block still works as a compatibility fallback. The shipped bootstrap convention is fully keychain-backed: `servers.<url>.auth.username_keychain_account=corp-vpn/username` and `servers.<url>.auth.password_keychain_account=corp-vpn/password`. Plain `username` remains as a compatibility fallback. `totp_secret_keychain_account` stays optional and is intentionally not wired by default.
- live auth now defaults to `--auth aggregate`, which is the only path that currently completes the example SSO+CSD flow on this machine; `--auth openconnect` remains available as the direct `openconnect --authenticate` path for debugging. `vpn-auth` is used for the browser-assisted SAML steps in aggregate mode, with preset-cookie support for follow-up pages.
- `./scripts/setup.sh` now treats the full live runtime as part of the shipped toolchain: it ensures `sing-box` for `vless-tun`, `totp-cli` for `vpn-auth`, builds `desktop/cmd/vpn-auth`, installs the resulting binary into `~/.local/bin`, and `./scripts/deinit.sh` removes that managed binary link again.
- the CSD helper is resolved from the active OpenConnect install, preferring native Cisco `libcsd.dylib` when it is available under `~/.cisco/...`; otherwise it falls back to Homebrew's stable `opt/openconnect/libexec/openconnect/csd-post.sh` path instead of versioned `Cellar/...` paths. The fallback `csd-post.sh` path is still wrapped with tiny macOS shims for `pidof` and GNU-style `stat -c %Y`.
- `dump` is now the canonical activity-oriented name for packet diagnostics. `cisco-dump` remains installed as a compatibility alias, while runtime state stays under `~/.cache/cisco-dump` for continuity.
- `dump` keeps its own runtime state under `~/.cache/cisco-dump`, with session logs in `~/.cache/cisco-dump/sessions`, the current session pointer in `~/.cache/cisco-dump/runtime/current-session.json`, mirrored Cisco logs and cache artifacts under each session directory, tracked Cisco per-pid `lsof` snapshots, all-loopback TCP snapshots from `lsof`/`netstat`, a default tunnel-aware traffic capture pcap, a separate loopback OCSC pcap, and host-level DNS/route/TCP/HTTPS probe snapshots for the anonymized example targets.
- `dump start` now defaults to `pktap,all` with a broad `tcp or udp` filter so tunnel traffic on `utun*`, loopback IPC, and ordinary uplink traffic are captured in one session. A separate `localhost-loopback.pcap` sidecar is still recorded so OCSC decoding remains stable.
- when a `dump` session stops with an OCSC loopback pcap present, it now also derives `ocsc-timeline.txt` and `ocsc-summary.txt` from AnyConnect OCSC loopback traffic. `dump inspect --session-id ...` can re-run that decoder on an older captured session.
- `dump start` now defaults to probing `gitlab.services.corp.example` and `portal.corp.example`; pass `--probe-host`, `--probe-ns`, or `--no-host-probes` when you need a different target set.
- live `dump` `tcpdump` capture now prefers the shared `vpn-core` backend when it is installed, and falls back to `sudo` otherwise. The rest of the diagnostic session stays in user space.
- live `start` now emits compact `auth_stage:` updates in the terminal during authentication instead of forcing you to tail the session log for every auth transition. The full detailed auth log still stays in the session log file.
- live `start` now resolves the privileged backend automatically: shared `vpn-core` first when it is installed, otherwise the old `sudo -v` + `sudo -n` path so the privileged password prompt still does not compete with the cookie being piped into `--cookie-on-stdin`.
- `--mode full` uses the stock `vpnc-script`, so OpenConnect will own default route and global DNS. Treat it as a smoke-test path, not a coexistence-safe mode.
- `--mode split-include` uses `vpn-slice`. On macOS that means scoped `/etc/resolver/<domain>` files for VPN DNS instead of replacing the global resolver stack, which is the direction we want for split-include coexistence next to `vless-tun`.
- host trust and guest trust are separate concerns. A macOS host may trust a corporate CA in Keychain while a Colima or Docker VM still rejects the same internal registry with `x509: certificate signed by unknown authority`. If an internal registry is reachable from the host but `docker pull` fails inside the guest, install the corporate CA into the guest trust store or into `/etc/docker/certs.d/<registry>/ca.crt` on the daemon host.

### `openconnect-tun setup`

Scaffolds a default `openconnect-tun` config and the matching keychain account names for one VPN profile.

Pass `--vpn-name` with the user-facing AnyConnect profile name. `setup` resolves the matching `server_url` from local AnyConnect XML, writes a default full-mode config with no bypasses, seeds placeholder keychain entries for username/password/TOTP, and prints the resulting config path so the caller can review it.

If TOTP starts from a Google Authenticator export QR, use `./scripts/google-auth-export-secret.sh`. The export URL contains a URL-encoded base64 protobuf payload, but the final Keychain value for `totp_secret` must be the derived base32 secret:

```bash
./scripts/google-auth-export-secret.sh 'otpauth-migration://offline?...'
./scripts/google-auth-export-secret.sh --list 'otpauth-migration://offline?...'
```

#### `openconnect-tun` configuration

Default live config path:

- `~/.config/openconnect-tun/config.json`

Example config:

```json
{
  "cache_dir": "~/.cache/openconnect-tun",
  "default": {
    "server_url": "vpn-gw2.corp.example/outside",
    "profile": "Ural Outside extended"
  },
  "servers": {
    "vpn-gw2.corp.example/outside": {
      "auth": {
        "username_keychain_account": "corp-vpn/username",
        "password_keychain_account": "corp-vpn/password"
      },
      "profiles": {
        "Ural Outside extended": {
          "mode": "split-include",
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
              "corp.example",
              "corp-it.example",
              "corp-it.internal",
              "erp.example",
              "short.example",
              "corp-sec.example",
              "branch.example"
            ],
            "bypass_suffixes": [
              "vpn-gw2.corp.example",
              "bypass.corp.example"
            ]
          }
        },
        "Public Corp": {
          "mode": "full"
        }
      }
    }
  }
}
```

Field reference:

- `cache_dir`: local runtime/state directory for `openconnect-tun`. This is where the CLI keeps its own ephemeral artifacts, not user-authored config.
- `cache_dir` session logs: `~/.cache/openconnect-tun/sessions/openconnect-session-<UTC timestamp>.log`
- `cache_dir` runtime metadata: `~/.cache/openconnect-tun/runtime/current-session.json`
- `cache_dir` helper/runtime logs: files under `~/.cache/openconnect-tun/runtime/`, such as orphan-cleanup logs
- `cache_dir` separation: intentionally separate from `~/.cache/vless-tun`, so the two tunnel stacks do not overwrite each other's runtime state
- `default.server_url`: the default OpenConnect target when `start|reconnect` runs without an explicit `--server`
- `default.profile`: the default user-facing profile selector when `start|reconnect` runs without an explicit `--profile`
- `default` pairing: these two fields are meant to point at the same configured VPN choice, so the config reads as one default selection instead of separate root-level knobs
- `servers.<url>`: configuration bucket for one concrete ASA endpoint such as `vpn-gw2.corp.example/outside`
- `servers.<url>.auth`: preferred auth override for that concrete server. Use this when different ASA endpoints require different keychain entries or usernames
- `servers.<url>.profiles.<profile>`: one user-facing profile variant under that server; this is where `mode` and `split_include` live
- legacy auth fallback: root-level `auth` is still accepted for older configs, but new configs should prefer `servers.<url>.auth`
- `servers.<url>.profiles.<profile>.mode`: default connect mode for that profile. Use `split-include` for coexistence-safe split routing or `full` for stock full-tunnel behavior
- `servers.<url>.profiles.<profile>.split_include.routes`: included CIDRs, hosts, or aliases passed to `vpn-slice` in split-include mode
- `servers.<url>.profiles.<profile>.split_include.nameservers`: scoped VPN DNS servers to use for that profile
- `servers.<url>.profiles.<profile>.split_include.vpn_domains`: suffix masks, not exact-only hostnames. `corp.example` already covers `*.corp.example`, so do not also list covered entries like `inside.corp.example` or `region.corp.example`
- `servers.<url>.profiles.<profile>.split_include.vpn_domains` normalization: the CLI now collapses covered suffixes automatically during option resolution, but the config should still stay clean and minimal
- `servers.<url>.profiles.<profile>.split_include.bypass_suffixes`: suffixes that must stay on the public resolver path even when a broader VPN suffix also matches
- `split_include.bypass_suffixes` semantics: on macOS `openconnect-tun` implements bypasses by writing a more specific public `/etc/resolver/<suffix>` entry over the broader VPN-scoped resolver, so `bypass.corp.example` can stay public while `corp.example` still uses VPN DNS
- built-in example augmentation: for the anonymized `/outside` example targets `openconnect-tun` still augments split DNS with the extra official Cisco suffix set (`inside.corp.example`, `region.corp.example`, `branch.example`, `workspace.example`, and related domains), so the config can stay minimal without manually restating every covered subdomain

### `vless-tun setup`

Creates `~/.config/vless-tun/config.json` by default using the preferred schema.

Use `--source-url` for either an HTTP subscription endpoint or a literal `vless://...` URI. `setup` prints the resulting config path so the caller can review it immediately.

### `vless-tun init`

Creates `~/.config/vless-tun/config.json` by default.

`init` remains as the compatibility entrypoint. `--subscription-url` remains the compatibility flag name, but the preferred config shape now writes it into `source.url`.

### `vless-tun refresh`

Refreshes the configured VLESS source, parses all available `vless://` profiles, and writes a local cache snapshot.

`source.mode=proxy` means `source.url` is fetched over HTTP and expected to resolve to one or more `vless://` entries. `source.mode=direct` means `source.url` already contains a literal `vless://...` URI and no extra fetch indirection is used.

### `vless-tun list`

Shows the cached profiles in a compact form. Use `--refresh` if you want it to pull the subscription first.

### `vless-tun start`

Renders the selected profile to the configured sing-box JSON and then starts `sing-box` in the background.

When `vless-tun` is running in `network.mode=tun` above an active `openconnect-tun` split-include session, `start` now waits for overlay DNS convergence before returning. In that overlay mode, a live `sing-box` PID alone is not treated as ready; the CLI also waits for the system public resolver path to settle so follow-up terminal clients do not race the DNS handoff.

Each start creates a new timestamped session log and metadata pair under:

- `~/.cache/vless-tun/sessions/sing-box-session-<UTC timestamp>.log`
- `~/.cache/vless-tun/sessions/session-<UTC timestamp>.json`

The currently active session pointer is stored at:

- `~/.cache/vless-tun/runtime/current-session.json`

`start` is the command that should actually bring the tunnel up. `status` does not connect anything by itself.

In `network.mode=tun`, `start` resolves the launch backend automatically. If the shared `vpn-core` daemon is installed, that is the preferred happy-path backend. An explicit `launch` block is only needed as an override for fallback or debugging:

- `auto`: resolve to shared `vpn-core` when it is installed, otherwise `sudo` for TUN as a regular user and `direct` when already root
- `sudo`: run `sudo sing-box run -c ...` after caching credentials with `sudo -v`
- `direct`: run `sing-box` directly; intended for already-root environments
- `helper`: spawn and stop root `sing-box` through the shared `vpn-core` daemon
- `launchd`: compatibility alias for `helper`; the long-lived LaunchDaemon now belongs to `vpn-core`, not to each `sing-box` session

### `vless-tun reconnect`

Reloads the local config, refreshes the subscription cache by default, rerenders the selected profile, stops any currently recorded session, and starts a fresh `sing-box` session.

This is the command to use after changing:

- `default.profile_selector`
- `routing.bypass_suffixes`
- `dns.proxy_resolver`
- `artifacts.singbox_config_path`
- any other render-time setting in `~/.config/vless-tun/config.json`

### `vless-tun status`

Shows the current local view of the tunnel state:

- whether a recorded `sing-box` session is active, stale, or absent
- the current session ID, PID, launch mode, start timestamp, and log file path
- whether the configured TUN interface exists
- whether the rendered config file exists
- which profile is selected from cache
- which bypass suffixes are configured
- which cached profiles are available

This is a heuristic runtime status, not a control plane.

### `vless-tun diagnose`

Prints a focused runtime diagnostic view for the current launch backend. When the effective launch backend resolves to `helper` or `launchd`, it checks the shared `vpn-core` daemon and reports the current socket and daemon PID.

### `vless-tun stop`

Stops the currently recorded `sing-box` session using `SIGTERM` by default. Use `--force` if you want it to escalate to `SIGKILL` after the timeout.

### `vless-tun render`

Selects a cached profile and writes a sing-box JSON config with:

- a TUN inbound
- proxy detour for the rest of the traffic
- optional direct DNS and direct outbound for configured suffix bypasses

If `routing.bypass_suffixes` is empty, the renderer produces a simple full-tunnel config with no suffix-based bypasses.

## Local Config

Default live config path:

- `~/.config/vless-tun/config.json`

Repo-local example:

- `configs/local.example.json`

If you want to keep using a repo-local config, pass `--config`.

Example config:

```json
{
  "cache_dir": "~/.cache/vless-tun",
  "source": {
    "mode": "proxy",
    "url": "https://key.vpn.dance/connect?key=REPLACE_ME"
  },
  "network": {
    "mode": "tun",
    "tun": {
      "interface_name": "utun233",
      "addresses": [
        "172.19.0.1/30",
        "fdfe:dcba:9876::1/126"
      ]
    }
  },
  "routing": {
    "bypass_suffixes": [
      ".ru",
      ".рф"
    ]
  },
  "dns": {
    "proxy_resolver": {
      "address": "1.1.1.1",
      "port": 853,
      "tls_server_name": "cloudflare-dns.com"
    }
  },
  "logging": {
    "level": "info"
  },
  "artifacts": {
    "singbox_config_path": "~/.config/vless-tun/generated/sing-box.json"
  }
}
```

Field reference:

- `cache_dir`: local runtime/cache directory for refresh snapshots, session logs, and runtime metadata
- `source.mode`: `proxy` or `direct`
- `source.url`: the actual source address; in `proxy` mode this is an HTTP endpoint that resolves to one or more `vless://` entries, and in `direct` mode this is a literal `vless://...` URI
- `default.profile_selector`: optional selector by exact id, exact name, or substring when the source resolves to multiple profiles
- `network.mode`: currently `tun`
- `network.tun.interface_name`: TUN interface name for `tun` mode
- `network.tun.addresses`: TUN addresses for `tun` mode
- `routing.bypass_suffixes`: domains that should go `direct`; set `[]` for full-tunnel bring-up
- `routing.bypass_exclude_suffixes`: optional suffixes that must stay on proxy even when a broader bypass list exists
- `dns.proxy_resolver`: upstream DNS endpoint for proxied traffic
- `logging.level`: sing-box log level written into the generated config
- `artifacts.singbox_config_path`: provider-neutral generated sing-box config artifact path
- `launch.mode`: optional override for the runtime backend. Omit `launch` in the happy path and `vless-tun` will resolve to the shared `vpn-core` backend automatically when it is available
- `launch.label` and `launch.plist_path`: legacy compatibility overrides only; the shared daemon now belongs to `vpn-core`, not to each `sing-box` session

### Full TUN on macOS

Example config fragment for a real TUN session managed by the shared `vpn-core` daemon without any explicit launch override:

```json
{
  "network": {
    "mode": "tun",
    "tun": {
      "interface_name": "utun233",
      "addresses": [
        "172.19.0.1/30",
        "fdfe:dcba:9876::1/126"
      ]
    }
  }
}
```

Then run:

```bash
vpn-core install
vless-tun reconnect --refresh
vless-tun status
```

## Development

```bash
go fmt ./...
go test ./...
go build -o vless-tun ./desktop/cmd/vless-tun
go build -o openconnect-tun ./desktop/cmd/openconnect-tun
go build -o dump ./desktop/cmd/dump
go build -o cisco-dump ./desktop/cmd/cisco-dump
```

## Notes

- This version manages the local `sing-box` session lifecycle with `start`, `status`, `stop`, and a configurable privileged TUN backend for macOS.
- `reconnect` is the "apply latest config" path: it rereads local config, refreshes the subscription by default, rerenders, and replaces the current session.
- `status` is an introspection view over recorded session state, launch backend, process liveness, interface presence, and cached profile data; it is not a deep traffic verifier.
- If your public IP does not change, check the latest session log first. The expected control flow is `start` -> `status` -> inspect the session log, not `status` alone.
- `system_proxy` render mode has been removed; legacy configs should use `network.mode=tun` and drop any old `network.system_proxy` block.
- Design note: [Why `vless-tun` stays TUN-only](artifacts/v2raytun-localhost-vs-vless-tun/README.md)
- Generated config now includes `route.default_domain_resolver`, which `sing-box 1.13.x` expects as part of the DNS resolver migration path.
- Every `start` gets its own timestamped log file so later debugging has a stable artifact even if the next session behaves differently.
- The bypass rule is intentionally domain-suffix based because the original user requirement was `*.ru`. If later you want IP or community rulesets, extend the renderer rather than hardcoding provider-specific blobs.
