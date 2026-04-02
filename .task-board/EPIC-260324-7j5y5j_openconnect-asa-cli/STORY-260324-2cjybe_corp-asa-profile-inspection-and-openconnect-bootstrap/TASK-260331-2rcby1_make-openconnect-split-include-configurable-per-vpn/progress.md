## Status
to-review

## Assigned To
codex

## Created
2026-03-31T13:53:31Z

## Last Update
2026-04-01T10:47:31Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Evidence: AnyConnect session 20260331T134238Z resolved portal.corp.example publicly to 203.0.113.27 and routed via en0, while openconnect session 20260331T134831Z resolved it via VPN DNS to 10.25.1.4 and routed via utun9. Current openconnect config only supports one global split_include block, so per-VPN behavior cannot be expressed cleanly.
Implemented config-layer override support: global split_include now falls back to profiles.<name>.split_include and servers.<host/path>.split_include with profile > server > global precedence and replacement semantics per list field. Added parser tests for profile override, server override, precedence, and explicit list clearing.
Verification: go test ./internal/openconnectcli/... and go test ./internal/openconnect/... ./internal/openconnectcfg/... passed on 2026-03-31 after the config override changes.
2026-04-01 follow-up evidence: user reran the matrix and confirmed portal remains the unresolved classification edge case. Official AnyConnect-only behavior still differs from openconnect-tun standalone, so per-VPN/per-domain split-include configurability is likely still needed after the primary resolver/route investigation completes.

## Precondition Resources
(none)

## Outcome Resources
(none)
