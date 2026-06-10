# Release Notes

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
