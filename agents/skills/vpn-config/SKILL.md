---
name: vpn-config
description: >
  Manage DenseVPN / DanceVPN VLESS subscriptions, render sing-box configs, and control local
  macOS VPN sessions through `vless-tun`. Supports refresh/list/render flows, real TUN or
  system-proxy mode, privileged `launchd` bring-up, suffix bypasses, and runtime diagnostics.
triggers:
  - vpn-config
  - dancevpn
  - densevpn
  - sing-box
  - singbox
  - vless-tun
  - tun mode
  - launchd vpn
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

Use the local `vless-tun` CLI when the task is about DenseVPN / DanceVPN subscriptions or generating sing-box client configs.

When the repo board is involved, pair this skill with `project-management`: `multi-tun` is a board-driven repo and `task-board` must stay current before and during implementation.

## Core Capabilities

- initialize local config and keep the live subscription URL in `~/.config/vless-tun/config.json`
- refresh, parse, and inspect cached `vless://` profiles from DenseVPN / DanceVPN subscriptions
- render `sing-box` configs for `system_proxy` or real `tun` mode
- manage privileged macOS TUN bring-up with `render.privileged_launch`, including `launchd`
- control session lifecycle with `run`, `reconnect`, `status`, `diagnose`, and `stop`
- apply suffix-based direct bypasses such as `.ru` / `.рф`
- inspect session logs, rendered config paths, launch backend state, and active interface details

## Quick Start

```bash
vless-tun init
vless-tun refresh
vless-tun list
vless-tun run
vless-tun reconnect
vless-tun status
vless-tun diagnose
vless-tun stop
vless-tun render
```

## Workflow

1. Ensure `~/.config/vless-tun/config.json` exists.
2. Refresh the subscription cache.
3. Inspect available profiles if the subscription contains more than one endpoint.
4. Use `run` when you need an actual background VPN session.
5. Use `reconnect` after changing bypasses, profile selection, or other render-time config so the live session picks up the new state.
6. On macOS, prefer `render.mode=system_proxy` for initial bring-up; use `render.mode=tun` with `render.privileged_launch` when you need a real TUN session.
7. Use `status`, `diagnose`, and the per-session log file to debug behavior.
8. In this repo, select or create the relevant `task-board` item before implementation and keep status/notes aligned with reality as the work progresses.
9. If command, setup, or config layout changes, update `README.md`, `SPEC.md`, `AGENTS.md`, and the task board.

## Command Summary

- `vless-tun init`
- `vless-tun refresh`
- `vless-tun list`
- `vless-tun run`
- `vless-tun reconnect`
- `vless-tun status`
- `vless-tun diagnose`
- `vless-tun stop`
- `vless-tun render`

## Rules

- Keep the live subscription URL in `~/.config/vless-tun/config.json`, not in committed examples.
- Do not hand-edit `.task-board/`; use `task-board`.
- Use the `project-management` skill for board work; don't invent parallel tracking outside `task-board`.
- Prefer extending the renderer and tests over adding one-off shell snippets.

## References

- [CLI Commands](references/cli-commands.md)
- [Config Layout](references/config-layout.md)
