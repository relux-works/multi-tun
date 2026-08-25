---
name: vpn-config
description: Manage and scaffold generic VLESS and OpenConnect tunnel configurations on macOS, render and diagnose vless-tun sessions, select openconnect-tun profiles, and safely import a Google Authenticator export QR image into the macOS Keychain without printing or persisting the TOTP secret. Use for vless-tun, openconnect-tun, sing-box, VPN configuration templates, subscription refresh, tunnel diagnostics, TOTP QR export, Keychain import, настройка VPN, VLESS, OpenConnect, экспорт Google Authenticator, and TOTP.
---

# VPN Config

Use the local `vless-tun` and `openconnect-tun` CLIs for tunnel configuration and lifecycle work. Keep live endpoints, subscription keys, credentials, QR payloads, and TOTP secrets out of committed files, logs, prompts, and command arguments.

## Start Here

1. Read [Config Layout](references/config-layout.md) before creating or editing a config.
2. Copy the matching file from `assets/` and replace only documented placeholders.
3. Keep VLESS URLs local. Never publish a subscription URL, UUID, Reality public key, short ID, or endpoint copied from a live config.
4. Keep OpenConnect credentials in the macOS Keychain service `multi-tun`; configs contain only Keychain account names.
5. Use [Safe TOTP Import](references/safe-totp-import.md) when the user provides a Google Authenticator export image path.
6. Validate JSON and run a dry diagnostic before starting a tunnel.

Resolve the directory containing this `SKILL.md` as `VPN_CONFIG_SKILL_DIR` before using bundled assets or scripts.

## Generic Config Workflow

### VLESS

```bash
cp "$VPN_CONFIG_SKILL_DIR/assets/vless-tun-config.template.json" ~/.config/vless-tun/config.json
chmod 600 ~/.config/vless-tun/config.json
vless-tun refresh --config ~/.config/vless-tun/config.json
vless-tun list --config ~/.config/vless-tun/config.json
vless-tun diagnose config --config ~/.config/vless-tun/config.json
vless-tun render --config ~/.config/vless-tun/config.json
```

Use either a proxy subscription URL or a direct `vless://` URI. Remove the unused example server after replacing placeholders. Prefer `vless-tun set-current server [profile]` over maintaining duplicate config files.

### OpenConnect

```bash
cp "$VPN_CONFIG_SKILL_DIR/assets/openconnect-tun-config.template.json" ~/.config/openconnect-tun/config.json
chmod 600 ~/.config/openconnect-tun/config.json
openconnect-tun profiles
openconnect-tun start example-corp engineering --dry-run
```

Replace the example server URL, profile label, and Keychain account names. Do not put a username, password, OTP, or TOTP secret directly in JSON.

## Safe Google Authenticator Import

The user exports accounts in Google Authenticator, saves the displayed QR as a local image, and gives the agent the image path. The agent then reads the Keychain account name from the OpenConnect config and runs:

```bash
"$VPN_CONFIG_SKILL_DIR/scripts/import-google-auth-qr-to-keychain.sh" \
  --image '/absolute/path/to/export.png' \
  --keychain-account 'example-vpn/totp-secret'
```

The importer captures the QR payload in memory, decodes the migration protobuf, converts the raw secret to unpadded base32, and sends it over stdin to a Security.framework Keychain writer. It prints only a success message with the account and service names.

Never inspect an authenticator QR through vision/OCR, paste its payload into chat, pass it as a command argument, write it to a temporary file, or run the decoder's secret-only output interactively. If the export contains multiple accounts, select one inside the safe importer with `--entry-index`, `--issuer`, or `--account`.

## Lifecycle Summary

```bash
vless-tun refresh
vless-tun list
vless-tun set-current example-subscription default
vless-tun start
vless-tun status
vless-tun diagnose
vless-tun reconnect
vless-tun stop

openconnect-tun set-current example-corp engineering
openconnect-tun start example-corp engineering
openconnect-tun status
openconnect-tun reconnect example-corp engineering
openconnect-tun stop
```

Use `network.mode=tun` for VLESS. Use `reconnect` after changing profile selection, routing, DNS, or other render-time fields.

## Validation

```bash
jq empty ~/.config/vless-tun/config.json
jq empty ~/.config/openconnect-tun/config.json
vless-tun diagnose config --config ~/.config/vless-tun/config.json
openconnect-tun start example-corp engineering --config ~/.config/openconnect-tun/config.json --dry-run
```

Before sharing a config, scan it for local paths, raw credentials, live URLs, UUIDs, subscription keys, and provider-specific names. Share placeholders only.

## References

- [Config Layout](references/config-layout.md)
- [CLI Commands](references/cli-commands.md)
- [Safe TOTP Import](references/safe-totp-import.md)
