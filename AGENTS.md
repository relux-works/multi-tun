# Repository Guidelines

## Project Structure & Module Organization

- `cmd/vless-tun/`: VLESS CLI entry point.
- `cmd/openconnect-tun/`: OpenConnect inspection CLI entry point.
- `internal/config/`: local project config loading and initialization.
- `internal/model/`: shared subscription/profile models.
- `internal/subscription/`: subscription fetch, decoding, cache snapshot handling, VLESS parsing.
- `internal/singbox/`: sing-box config rendering for DenseVPN profiles.
- `internal/openconnect/`: AnyConnect CLI and XML inspection helpers.
- `agents/skills/vpn-config/`: installed skill payload for agent runtimes.
- `scripts/setup.sh`: builds the binary and installs the local skill.
- `configs/`: example local config and generated sing-box output.
- `fixtures/`: sanitized subscription payloads for parser tests.
- Existing docs in the repo capture field notes from live VPN investigation and should stay intact.

## Build, Test, and Development Commands

Run from repo root:

- `./scripts/setup.sh`: build `vless-tun` and `openconnect-tun`, symlink them into `~/.local/bin`, install the skill payload.
- `go build -o vless-tun ./cmd/vless-tun`: local build without installation.
- `go build -o openconnect-tun ./cmd/openconnect-tun`: local build without installation.
- `go test ./...`: run unit tests.
- `go fmt ./...`: format all Go packages.
- `vless-tun init`: create `configs/local.json` from defaults.
- `vless-tun refresh`: fetch and decode the current DanceVPN subscription.
- `vless-tun run`: render and start a background sing-box session with per-session logs.
- `vless-tun status`: inspect local runtime state, cached profiles, and configured bypasses.
- `vless-tun stop`: stop the current sing-box session.
- `vless-tun render`: generate a sing-box config from the cached subscription snapshot.
- `openconnect-tun status`: inspect Cisco AnyConnect CLI state and active ASA connection info.
- `openconnect-tun profiles`: list profiles returned by `vpn hosts`.
- `openconnect-tun inspect-profiles`: inspect local AnyConnect XML profiles for bypass-relevant flags and server entries.

## Board Workflow

- This repo uses `task-board` with `task-board.config.json`.
- Board-first discipline is mandatory here: create or select the relevant board element before implementation starts.
- Use the `project-management` skill whenever the task involves planning, decomposition, status, dependencies, or board updates.
- Do not edit `.task-board/` manually. All board writes go through `task-board m ...`.
- Keep the board aligned with shipped scope while you work: assignment, status, notes, checklist, and linked artifacts should reflect reality.
- If a user-facing command, setup flow, local runtime wiring, or agent workflow changes, update the board notes and related docs in the same slice.

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
- Keep repo-local agent runtime wiring current. `agents-infra setup local <repo>` is the baseline, and project-specific instructions/skills must still be layered on top for spawned agents.
