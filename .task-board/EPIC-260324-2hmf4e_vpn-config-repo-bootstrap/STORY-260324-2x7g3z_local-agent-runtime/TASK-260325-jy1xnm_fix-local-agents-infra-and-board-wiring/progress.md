## Status
to-review

## Assigned To
codex

## Created
2026-03-24T21:32:14Z

## Last Update
2026-03-24T21:36:06Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Started audit of repo-local agents-infra setup. Need to distinguish true alexis-agents-infra bug from missing multi-tun project wiring after repo rename.
Findings: alexis-agents-infra itself was healthy after sequential setup/doctor; the real gap was missing project-local wiring in multi-tun after the repo rename. Fixes: scripts/setup.sh now runs agents-infra setup local when available, copies agents/instructions/INSTRUCTIONS_PROJECT.md into .agents/.instructions/, appends that overlay to AGENTS.md and INSTRUCTIONS.md, and links vpn-config plus project-management into repo-local .agents/.claude/.codex skills. Verification: bash -n scripts/setup.sh, ./scripts/setup.sh, agents-infra doctor local /Users/alexis/src/multi-tun => all core links true; local instruction entrypoints include INSTRUCTIONS_PROJECT.md; local skills show vpn-config and project-management.

## Precondition Resources
(none)

## Outcome Resources
(none)
