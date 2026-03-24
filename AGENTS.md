# Repository Guidelines

## Project Structure & Module Organization

- `cmd/vpn-config/`: CLI entry point.
- `internal/config/`: local project config loading and initialization.
- `internal/model/`: shared subscription/profile models.
- `internal/subscription/`: subscription fetch, decoding, cache snapshot handling, VLESS parsing.
- `internal/singbox/`: sing-box config rendering for DenseVPN profiles.
- `agents/skills/vpn-config/`: installed skill payload for agent runtimes.
- `scripts/setup.sh`: builds the binary and installs the local skill.
- `configs/`: example local config and generated sing-box output.
- `fixtures/`: sanitized subscription payloads for parser tests.
- Existing docs in the repo capture field notes from live VPN investigation and should stay intact.

## Build, Test, and Development Commands

Run from repo root:

- `./scripts/setup.sh`: build `vless-tun`, symlink it into `~/.local/bin`, install the skill payload.
- `go build -o vless-tun ./cmd/vpn-config`: local build without installation.
- `go test ./...`: run unit tests.
- `go fmt ./...`: format all Go packages.
- `vless-tun init`: create `configs/local.json` from defaults.
- `vless-tun refresh`: fetch and decode the current DanceVPN subscription.
- `vless-tun run`: render and start a background sing-box session with per-session logs.
- `vless-tun status`: inspect local runtime state, cached profiles, and configured bypasses.
- `vless-tun stop`: stop the current sing-box session.
- `vless-tun render`: generate a sing-box config from the cached subscription snapshot.

## Board Workflow

- This repo uses `task-board` with `task-board.config.json`.
- Do not edit `.task-board/` manually. All board writes go through `task-board m ...`.
- Keep the board aligned with shipped scope. If a user-facing command or workflow changes, update the board notes and related docs.

## Coding Style & Naming Conventions

- Keep Go code `gofmt`-clean.
- Prefer standard library unless an external dependency materially reduces maintenance cost.
- Keep CLI output concise and stable so agents can parse it.
- Treat subscription URLs and generated local configs as secrets; they belong in `configs/local.json` or `.cache/`, never in committed examples.

## Testing Guidelines

- Use table-driven tests for parsing and rendering logic.
- Keep tests offline; use fixtures instead of live network calls.
- If you change generated sing-box JSON shape, update or add assertions in `internal/singbox/render_test.go`.

## Documentation Expectations

- Update `README.md` when command UX or setup changes.
- Update `SPEC.md` when scope changes.
- Update `agents/skills/vpn-config/SKILL.md` and references when the recommended agent workflow changes.
