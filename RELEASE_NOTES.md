# Release Notes

## v1.3.4 - Selectorless Dance TCP profile fallback

Tag: `v1.3.4`
Base tag: `v1.3.3`

This release fixes a selectorless VLESS profile-selection failure mode observed on the Dance provider. The subscription currently lists a gRPC transport before a TCP/no-transport entry; selectorless startup used to pick the first provider entry, which selected the gRPC profile and correlated with a severe long-running `sing-box` CPU/RSS storm.

### Highlights

- Empty or whitespace profile selectors now prefer a stable `tcp`/no-transport profile before falling back to provider order.
- Explicit selectors still work for `grpc` and other supported profiles.
- Dance selectorless `default` now renders `152.53.107.138:8444 | tcp` instead of `152.53.107.138:8443 | grpc`.
- README and SPEC now document selectorless automatic profile selection semantics.

### Operational notes

- Existing configs do not need migration.
- If a provider has only gRPC profiles, selectorless selection still falls back to provider order.
- Operators can still pin a specific profile through `servers.<name>.profiles.<profile>.selector`.

### Validation performed for this release

```bash
go test ./desktop/internal/vless/subscription
go test ./desktop/internal/vless/subscription ./desktop/internal/vless/config ./desktop/internal/vless/cli ./desktop/internal/vless/singbox
go test ./...
git diff --check
sing-box check -c .temp/BUG-260612-pjbw1n/rendered-dance-postfix.json
vless-tun reconnect dance
vless-tun status dance
```

Live post-reconnect evidence:

- previous `sing-box` PID `54614`: `476.6%` CPU, `6880224 KB` RSS, selected `8443 | grpc`
- new `sing-box` PID `76128`: near-idle CPU, about `47088 KB` RSS, selected `8444 | tcp`

## v1.3.3 - Bounded VLESS runtime logging

Tag: `v1.3.3`
Base tag: `v1.3.2`

This release makes `vless-tun` runtime logging explicit and bounded. The high-CPU incident on `fortinetz` showed `sing-box` running in TUN mode with `logging.level=info`, producing about two million session-log lines and hundreds of percent CPU. `logging.level=warn` remains the normal runtime default, and helper-backed `sing-box` logs now retain only the configured tail.

### Highlights

- Added top-level `logging.max_lines`, defaulting to `1000`.
- Added validation for top-level `logging.level`.
- `vless-tun status` and `vless-tun diagnose config` now print `logging_level` and `logging_max_lines`.
- `vpn-core` accepts per-command log options and applies bounded tail retention to helper-backed long-running `sing-box` stdout/stderr.
- `vless-tun` internal runtime events now carry severity prefixes such as `[info]`, `[warn]`, and `[error]`.
- Verbose `trace`, `debug`, or `info` TUN starts print a warning: `max_lines` bounds disk growth, but the engine can still spend CPU logging every connection.

### Config compatibility

Existing v1.3.2 configs continue to load. If `logging.max_lines` is absent, the loaded default is `1000`.

For older configs, make the top-level `logging` section explicit:

```json
"logging": {
  "level": "warn",
  "max_lines": 1000
}
```

Valid `logging.level` values:

```text
trace, debug, info, warn, error, fatal, panic
```

Operational guidance:

- use `warn` for normal long-running TUN sessions
- use `info` or `debug` only for short diagnostics
- set `max_lines` to `0` only when intentionally collecting an unbounded log

### Agent upgrade checklist

Use this checklist when updating an existing machine from v1.3.2.

1. Back up the live config.

```bash
cp ~/.config/vless-tun/config.json ~/.config/vless-tun/config.json.bak-v1.3.3
```

2. Ensure the top-level `logging` section contains both fields.

```json
"logging": {
  "level": "warn",
  "max_lines": 1000
}
```

3. Rebuild and install the local toolchain.

```bash
./scripts/setup.sh
```

4. Restart the shared helper if it is already installed, so the LaunchDaemon uses the updated `vpn-core` binary.

```bash
vpn-core install
```

5. Verify config diagnostics before starting a tunnel.

```bash
vless-tun diagnose config fortinetz nl
```

Expected logging lines:

```text
logging_level: warn
logging_max_lines: 1000
```

6. Start normally.

```bash
vless-tun start fortinetz nl
```

### Operational notes

- Bounded retention applies to helper-backed `sing-box` frontend logs. This is the default happy path on macOS when `vpn-core` is installed.
- Xray sidecar logs remain separate under `xray-session-<timestamp>.log`; keep `logging.level=warn` unless collecting short diagnostics.
- Old oversized session logs can be truncated safely after the session is stopped.

### Validation performed for this release

```bash
go test ./...
git diff --check
vless-tun diagnose config fortinetz nl
vless-tun status fortinetz
```

## v1.3.2 - VLESS profile alias mismatch diagnostics

Tag: `v1.3.2`
Base tag: `v1.3.1`

This release makes refreshed VLESS subscription drift fail with an actionable diagnostic instead of a bare selector error. If a configured profile alias such as `fortinetz nl` no longer matches any active profile after refresh, `vless-tun` now stops before rendering or startup and tells the operator exactly which config selector needs updating.

### Highlights

- `vless-tun start`, `run`, `render`, and `reconnect` now preserve the effective server/profile alias while preparing the selected subscription profile.
- Profile selector misses now report:
  - configured server name
  - configured profile alias
  - selector value
  - whether the source was a refreshed or cached subscription snapshot
  - original match failure reason
  - available profiles from the current snapshot
  - the exact `servers.<server>.profiles.<alias>.selector` path to update
- `--refresh=false` keeps using the cached snapshot, and the diagnostic labels the profile list as cached so offline starts are unambiguous.
- Documentation now calls out the start-time failure mode for stale profile aliases.

### Config compatibility

No new config keys are required for v1.3.2.

Existing v1.3.1 configs continue to work unchanged. If a provider removes or renames a profile that your config alias points at, update only the selector for that alias:

```json
"profiles": {
  "nl": {
    "selector": "<id, name, endpoint, or substring from available profiles>"
  }
}
```

### Agent upgrade checklist

Use this checklist when updating an existing machine from v1.3.1.

1. Install or rebuild the updated CLI.

```bash
go build -o ~/.local/bin/vless-tun ./desktop/cmd/vless-tun
```

2. Start normally. Subscriptions still refresh by default before rendering.

```bash
vless-tun start fortinetz nl
```

3. If startup fails because `nl` no longer matches a refreshed profile, inspect the available profiles and update the configured selector.

```bash
vless-tun list fortinetz
```

Expected diagnostic shape:

```text
configured profile "nl" for server "fortinetz" did not match any refreshed subscription profile
selector: Netherlands
reason: profile selector "Netherlands" did not match any profile

available profiles:
- <id> | <name> | <endpoint> | <transport>

update config: servers.fortinetz.profiles.nl.selector = "<id, name, endpoint, or substring from available profiles>"
or run: vless-tun list fortinetz
```

4. Use the cached fallback only when you explicitly want to avoid subscription refresh:

```bash
vless-tun start fortinetz nl --refresh=false
```

### Operational notes

- This release does not change the default refresh-on-start behavior introduced in v1.3.1.
- The failure happens before generated configs are rendered and before the TUN runtime starts, so stale aliases should not leave behind half-started sessions.
- The same diagnostic path is shared by `start`, `run`, `render`, and `reconnect`.

### Validation performed for this release

```bash
go test ./desktop/internal/vless/cli ./desktop/internal/vless/config
go test ./...
git diff --check
vless-tun start --config .temp/BUG-260610-1sxa23/missing-profile-config.json fortinetz nl
vless-tun start --refresh=false --config .temp/BUG-260610-1sxa23/missing-profile-config.json fortinetz nl
vless-tun status
```

## v1.3.1 - VLESS subscription refresh and server-level command fixes

Tag: `v1.3.1`
Base tag: `v1.3.0`

This release tightens VLESS provider handling after the Xray engine migration. It fixes multi-profile server diagnostics and makes `start` refresh subscriptions by default for every selected server/profile, so provider-side Reality SNI, fingerprint, and endpoint changes are picked up before rendering.

### Highlights

- `vless-tun start` and `vless-tun run` now refresh the selected server subscription by default, including explicit profile aliases such as `fortinetz nl`.
- `--refresh=false` remains available as the explicit offline/cache fallback when the subscription endpoint is unavailable and the last cached snapshot is known-good.
- Server-level commands no longer require a selected profile when the server has multiple configured profile aliases:
  - `vless-tun refresh <server>`
  - `vless-tun list <server>`
  - `vless-tun status <server>`
  - `vless-tun diagnose config <server>`
- `status <server>` now reports the requested server instead of failing on `current.profile` from another server or drifting back to `current.server`.
- Documentation now describes refresh-on-start as the default lifecycle behavior.

### Config compatibility

No new config keys are required for v1.3.1.

Existing v1.3.0 configs continue to work unchanged:

- keep explicit `servers.<name>.engine.type` blocks from v1.3.0
- keep `sing-box` for normal VLESS Reality servers
- keep `xray` only for servers that need Xray-only VLESS fields such as `encryption=mlkem...`

### Agent upgrade checklist

Use this checklist when updating an existing machine from v1.3.0.

1. Install or rebuild the updated CLI.

```bash
go build -o ~/.local/bin/vless-tun ./desktop/cmd/vless-tun
```

2. Confirm `start` and `run` show refresh enabled by default.

```bash
vless-tun start --help
vless-tun run --help
```

Expected flag text:

```text
-refresh
    Fetch subscription before rendering and starting (default true)
```

3. Refresh and inspect each multi-profile provider without choosing a profile.

```bash
vless-tun refresh fortinetz
vless-tun list fortinetz
vless-tun diagnose config fortinetz
vless-tun status fortinetz
```

4. Render/check the explicit profiles you actually use.

```bash
vless-tun render fortinetz nl
sing-box check -c ~/.config/vless-tun/generated/sing-box_fortinetz.json
```

5. Start normally. The default path now refreshes first.

```bash
vless-tun start fortinetz nl
```

Use the cached fallback only when you explicitly want to avoid subscription refresh:

```bash
vless-tun start fortinetz nl --refresh=false
```

### Operational notes

- `refresh`, `list`, `status`, and `diagnose config` are now safe server-level probes for multi-profile servers.
- `start` is the lifecycle command that pulls fresh provider state before rendering. `status` still does not connect anything or refresh by default.
- If a provider changes SNI/fingerprint/Reality parameters, restarting with the new CLI should pick up the fresh subscription automatically.

### Validation performed for this release

```bash
go test ./desktop/internal/vless/cli ./desktop/internal/vless/config
go test ./...
git diff --check
vless-tun refresh fortinetz
vless-tun status fortinetz
vless-tun diagnose config fortinetz
vless-tun list fortinetz
vless-tun start --help
vless-tun run --help
```

## v1.3.0 - VLESS Xray engine and explicit config migration

Tag: `v1.3.0`
Base tag: `v1.2.1`

This release adds a second VLESS runtime engine path for profiles that require Xray-only VLESS fields, while keeping `sing-box` as the default TUN frontend and the default engine for existing servers.

### Highlights

- Added explicit per-server VLESS engine selection:
  - `servers.<name>.engine.type = "sing-box"`
  - `servers.<name>.engine.type = "xray"`
- Added Xray-core sidecar support for VLESS profiles with Xray-only query fields such as `encryption=mlkem...`.
- Added Xray sidecar rendering plus a `sing-box` TUN frontend that forwards proxied traffic to the local Xray SOCKS inbound.
- Added `singbox.sniff` and `singbox.tls` config blocks for sniffing, TLS fragmentation, TLS record fragmentation, fallback delay, and curve preferences.
- Added sidecar lifecycle metadata to `start`, `status`, `diagnose`, `stop`, and `reconnect`.
- Added scoped startup cleanup for stale sidecars. Cleanup matches the configured executable/name plus generated sidecar config path and does not broadly kill every `xray` process.
- Improved `status` without arguments: if exactly one configured server has an active session, `status` reports that active server instead of blindly reporting `current.server`.

### Config compatibility

Legacy flat configs still default to `sing-box`.

Multi-server configs must now set `servers.<name>.engine.type` explicitly for every configured server. This is intentional: runtime selection is security-sensitive and should be visible in review.

If an old multi-server config does not set the engine, validation fails with an error similar to:

```text
servers.dance.engine.type is required; set it to one of: sing-box, xray.
Example: "servers": { "dance": { "engine": { "type": "sing-box" } } }.
Use "xray" for the Xray sidecar engine
```

### Agent upgrade checklist

Use this checklist when upgrading an existing `~/.config/vless-tun/config.json`.

1. Back up the live config.

```bash
cp ~/.config/vless-tun/config.json ~/.config/vless-tun/config.json.bak-v1.3.0
```

2. For every existing server that should continue using the old `sing-box` behavior, add:

```json
"engine": {
  "type": "sing-box"
}
```

Example:

```json
{
  "servers": {
    "dance": {
      "source": {
        "mode": "proxy",
        "url": "https://key.vpn.dance/connect?key=REPLACE_ME"
      },
      "cache_dir": "~/.cache/vless-tun/dance",
      "artifacts": {
        "singbox_config_path": "~/.config/vless-tun/generated/sing-box_dance.json"
      },
      "engine": {
        "type": "sing-box"
      }
    }
  }
}
```

3. For a server that requires Xray-only VLESS fields, add an Xray sidecar engine block and a generated Xray config path:

```json
{
  "servers": {
    "freedom": {
      "artifacts": {
        "singbox_config_path": "~/.config/vless-tun/generated/sing-box_freedom.json",
        "xray_config_path": "~/.config/vless-tun/generated/xray_freedom.json"
      },
      "engine": {
        "type": "xray",
        "xray": {
          "executable": "/opt/homebrew/opt/xray/libexec/xray",
          "socks_listen": "127.0.0.1",
          "socks_port": 20808,
          "process_names": ["xray"]
        }
      }
    }
  }
}
```

Use `"xray"` as the executable if the Homebrew wrapper works in the target environment. Use the absolute `/opt/homebrew/opt/xray/libexec/xray` path on Apple Silicon Macs when the wrapper does not behave like a stable long-running sidecar.

4. Install Xray only on machines that use `engine.type = "xray"`.

```bash
brew install xray
xray version
```

5. Preserve existing server-local settings while adding engine blocks:

- `servers.<name>.source`
- `servers.<name>.cache_dir`
- `servers.<name>.artifacts.singbox_config_path`
- `servers.<name>.profiles`
- `servers.<name>.routing`
- root `network`, `dns`, `logging`, and `launch`

Do not move secrets into committed files.

6. Validate each upgraded server before starting it.

```bash
vless-tun diagnose config dance
vless-tun render dance
sing-box check -c ~/.config/vless-tun/generated/sing-box_dance.json

vless-tun diagnose config freedom
vless-tun render freedom
sing-box check -c ~/.config/vless-tun/generated/sing-box_freedom.json
/opt/homebrew/opt/xray/libexec/xray run -test -c ~/.config/vless-tun/generated/xray_freedom.json
```

7. Restart intentionally. Positional lifecycle commands do not have to mutate `current.server`.

```bash
vless-tun stop
vless-tun start freedom
vless-tun status
```

After the v1.3.0 status fix, plain `vless-tun status` reports the single active configured server even if `current.server` still points at a different server.

### Operational notes

- `sing-box` remains the TUN process for both engines.
- With `engine.type = "xray"`, Xray runs as a local SOCKS sidecar and `sing-box` points its proxy outbound at that local SOCKS inbound.
- `stop`, `reconnect`, and stale startup cleanup terminate recorded sidecars.
- Startup orphan cleanup is scoped by generated sidecar config path. It should remove stale sidecars from failed starts without touching unrelated Xray processes.
- If multiple configured servers are active at once, plain `status` falls back to `current.server`; use `vless-tun status <server>` to inspect a specific server.

### Validation performed for this release

```bash
go test ./...
jq . configs/local.example.json
vless-tun diagnose config freedom
vless-tun render freedom
sing-box check -c ~/.config/vless-tun/generated/sing-box_freedom.json
/opt/homebrew/opt/xray/libexec/xray run -test -c ~/.config/vless-tun/generated/xray_freedom.json
```
