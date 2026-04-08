---
name: vpn-config
description: >
  Manage DenseVPN / DanceVPN VLESS subscriptions, scaffold tunnel configs, render sing-box
  configs, and control local macOS VPN sessions through `vless-tun` and `openconnect-tun`.
  Supports setup/refresh/list/render flows, real TUN mode, shared `vpn-core` bring-up,
  suffix bypasses, and runtime diagnostics.
triggers:
  - vpn-config
  - dancevpn
  - densevpn
  - sing-box
  - singbox
  - vless-tun
  - tun mode
  - launchd vpn
  - vpn-core
  - vless subscription
  - refresh vpn profile
  - generate sing-box config
  - настроить впн
  - денсвпн
  - дансвпн
  - сигбокс
  - влесс
  - подписка впн
  - обнови профиль впн
---

# VPN Config Skill

Use the local tunnel CLIs when the task is about VLESS subscriptions, OpenConnect scaffolding, or generating sing-box client configs.

When the repo board is involved, pair this skill with `project-management`: `multi-tun` is a board-driven repo and `task-board` must stay current before and during implementation.

## Core Capabilities

- initialize local config and keep the live subscription URL in `~/.config/vless-tun/config.json`
- scaffold `vless-tun` and `openconnect-tun` configs through dedicated `setup` commands
- refresh, parse, and inspect cached `vless://` profiles from DenseVPN / DanceVPN subscriptions
- render `sing-box` configs for real `tun` mode
- manage privileged macOS TUN bring-up with the shared `vpn-core` helper backend by default, keeping `launch` as an override
- control session lifecycle with `run`, `reconnect`, `status`, `diagnose`, and `stop`
- apply suffix-based direct bypasses such as `.ru` / `.рф`
- inspect session logs, rendered config paths, launch backend state, and active interface details

## Quick Start

```bash
vless-tun setup --source-url "https://key.vpn.dance/connect?key=..."
vless-tun refresh
vless-tun list
vless-tun run
vless-tun reconnect
vless-tun status
vless-tun diagnose
vless-tun stop
vless-tun render
openconnect-tun setup --vpn-name "Corp VPN"
openconnect-tun status
openconnect-tun profiles
openconnect-tun inspect-profiles
openconnect-tun start --profile "Corp VPN"
openconnect-tun stop
```

## Workflow

1. Ensure the target tunnel config exists. Prefer `vless-tun setup` or `openconnect-tun setup` over legacy hand-written bootstrap.
2. For `vless-tun`, refresh the subscription cache.
3. Inspect available profiles if the subscription contains more than one endpoint.
4. Use `run` when you need an actual background VLESS session.
5. Use `reconnect` after changing bypasses, profile selection, or other render-time config so the live VLESS session picks up the new state.
6. For `vless-tun`, use `network.mode=tun`; `system_proxy` is no longer a supported render mode in this repo.
7. `openconnect-tun setup` seeds full-mode config with no bypasses plus placeholder keychain accounts; the caller should review the generated config path before first connect.
8. `./scripts/setup.sh` is the supported install path for the full `multi-tun` toolchain. It ensures `sing-box` for `vless-tun`, builds and installs the bundled `vpn-auth` helper, and installs its `totp-cli` prerequisite, so both VLESS runtime and aggregate OpenConnect auth should be treated as shipped capabilities, not manual prerequisites.
9. Use `status`, `diagnose`, and the per-session log file to debug behavior.
10. In this repo, select or create the relevant `task-board` item before implementation and keep status/notes aligned with reality as the work progresses.
11. If command, setup, or config layout changes, update `README.md`, `SPEC.md`, `AGENTS.md`, and the task board.

## OpenConnect Auth And TOTP

When a user asks how to populate OpenConnect auth after `openconnect-tun setup`, explain that the config stores Keychain account names and the actual secrets live in the macOS Keychain service `multi-tun`.

Typical flow:

1. Inspect the configured account names in `~/.config/openconnect-tun/config.json`.
2. Seed or replace the username/password/TOTP secret with `security add-generic-password -U`.
3. Verify the stored value with `security find-generic-password -a '<account>' -s multi-tun -w`.
4. For TOTP, generate a current code with `oathtool --totp -b "$(security find-generic-password -a '<totp_account>' -s multi-tun -w)"`.

If the user only has a Google Authenticator export QR, explain the format clearly:

- the export QR usually contains an `otpauth-migration://offline?...` URL
- the `data=` query param is a URL-encoded base64 protobuf payload
- that payload is not the final TOTP secret
- decode flow is: `URL decode -> base64 decode -> protobuf parse -> raw secret bytes -> base32 encode`
- the value to store in Keychain and pass to `oathtool --totp -b` is the final base32 secret

Prefer the repo helper script when needed:

```bash
./scripts/google-auth-export-secret.sh 'otpauth-migration://offline?...'
./scripts/google-auth-export-secret.sh --list 'otpauth-migration://offline?...'
```

The helper accepts the full `otpauth-migration://...` URL, a raw `data=...` fragment, or the raw URL-encoded base64 payload itself. Default output is just the base32 secret when exactly one entry matches. Use `--list` for `index<TAB>issuer<TAB>account<TAB>base32secret`.

When the user explicitly asks how to convert a Google Auth export URL or asks for a ready command, answer with a concrete example command and example output, not just the abstract decode flow. A good template is:

```bash
./scripts/google-auth-export-secret.sh 'otpauth-migration://offline?data=REDACTED_URLENCODED_BASE64_PAYLOAD'
```

Expected output:

```text
JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
```

If the user wants to inspect which account is inside the export, also show:

```bash
./scripts/google-auth-export-secret.sh --list 'otpauth-migration://offline?data=REDACTED_URLENCODED_BASE64_PAYLOAD'
```

Expected output:

```text
1	ExampleIssuer	alice@example.com	JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
```

Use concrete commands when answering, for example:

```bash
security add-generic-password -U -a 'corp-vpn/username' -s multi-tun -w 'alice'
security add-generic-password -U -a 'corp-vpn/password' -s multi-tun -w 'correct-horse-battery-staple'
security add-generic-password -U -a 'corp-vpn/totp_secret' -s multi-tun -w 'BASE32SECRET'

security find-generic-password -a 'corp-vpn/totp_secret' -s multi-tun -w
oathtool --totp -b "$(security find-generic-password -a 'corp-vpn/totp_secret' -s multi-tun -w)"
```

Do not tell the user to store raw secrets in the committed config. Keep the config pointing at keychain accounts and keep the values in Keychain.

## Command Summary

- `vless-tun setup`
- `vless-tun init`
- `vless-tun refresh`
- `vless-tun list`
- `vless-tun run`
- `vless-tun reconnect`
- `vless-tun status`
- `vless-tun diagnose`
- `vless-tun stop`
- `vless-tun render`
- `openconnect-tun setup`
- `openconnect-tun status`
- `openconnect-tun profiles`
- `openconnect-tun inspect-profiles`
- `openconnect-tun start`
- `openconnect-tun reconnect`
- `openconnect-tun stop`

## Rules

- Keep live VLESS source URLs and OpenConnect auth values in local config/keychain, not in committed examples.
- Do not hand-edit `.task-board/`; use `task-board`.
- Use the `project-management` skill for board work; don't invent parallel tracking outside `task-board`.
- Prefer extending the renderer and tests over adding one-off shell snippets.

## References

- [CLI Commands](references/cli-commands.md)
- [Config Layout](references/config-layout.md)
