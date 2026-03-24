# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-03-24

### 1644 — Privileged TUN Backend Added
- DECISION: Real macOS TUN path stays in `vpn-config` under `vless-tun`, not `skill-multi-tun`.
- FIX: Added `render.privileged_launch` with `auto`, `sudo`, `direct`, `launchd` in `internal/config/config.go`.
- FIX: Reworked session backend in `internal/session/session.go` and `internal/session/launchd.go` so `run/status/stop/reconnect` support launch-aware lifecycle and persisted launch metadata.
- SCOPE: `internal/cli/run_stop.go`, `internal/cli/status.go`, `configs/local.example.json`, `README.md`, `SPEC.md`, `agents/skills/vpn-config/SKILL.md`.
- STATUS: `go test ./...` passes. Live verification under Telegram still pending in `TASK-260324-hqt44c`.

### 1645 — Render Tests Were Behind Current Defaults
- ANOMALY: `internal/singbox/render_test.go` still expected empty `rule_set` when direct bypasses were disabled, but default config already injects `proxy-exceptions`.
- FIX: Updated render tests to match current `bypass_exclude_suffixes` behavior.
- STATUS: Resolved.
