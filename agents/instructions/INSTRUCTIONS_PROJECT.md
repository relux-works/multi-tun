# Project Instructions

## multi-tun

This repo is board-driven.

- Before implementation, select or create the relevant `task-board` element.
- Use the `project-management` skill whenever work touches planning, tracking, status, dependencies, or task decomposition.
- Never edit `.task-board/` manually. Use `task-board q ...` for reads and `task-board m ...` for writes.
- Keep the active board element aligned with reality: assignment, status, notes, checklist, and linked artifacts.
- If command UX, setup flow, local runtime wiring, or agent workflow changes, update the board notes plus `README.md`, `SPEC.md`, and `AGENTS.md`/skill guidance in the same slice.

## Local Runtime

- `agents-infra setup local <repo>` is the base local runtime bootstrap.
- Project-specific instructions are layered on top of that shared runtime from this file.
- The repo-local skill is `vpn-config` in `agents/skills/vpn-config/`.
- For VPN/runtime tasks, use `vpn-config`; for board workflow, use `project-management`.
