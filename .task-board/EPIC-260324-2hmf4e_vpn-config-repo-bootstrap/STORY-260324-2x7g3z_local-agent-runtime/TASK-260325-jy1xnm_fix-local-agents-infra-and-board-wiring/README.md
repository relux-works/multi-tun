# TASK-260325-jy1xnm: fix-local-agents-infra-and-board-wiring

## Description
Audit repo-local agents-infra setup after repo rename, fix missing project-local wiring, and reinforce board-first workflow for spawned agents.

## Scope
1. Verify whether alexis-agents-infra local setup is broken or healthy. 2. Fix multi-tun local runtime wiring on top of agents-infra. 3. Layer repo-specific instructions and expose repo/project-management skills locally. 4. Update docs and board notes.

## Acceptance Criteria
1. agents-infra doctor local reports a healthy repo-local runtime. 2. Repo-local instructions include a project-specific board-first layer. 3. vpn-config and project-management are visible in local skills for Claude/Codex. 4. README/SPEC/AGENTS and board notes reflect the new setup.
