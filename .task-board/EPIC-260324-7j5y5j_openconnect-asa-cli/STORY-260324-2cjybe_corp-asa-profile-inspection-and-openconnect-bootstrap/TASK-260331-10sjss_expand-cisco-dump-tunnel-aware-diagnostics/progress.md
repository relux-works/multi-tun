## Status
to-review

## Assigned To
codex

## Created
2026-03-31T20:34:28Z

## Last Update
2026-03-31T20:57:36Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Completed activity-oriented rename polish: dump is now the canonical installed binary, cisco-dump remains a compatibility alias, CLI usage/output derives the invoked command name dynamically, and setup/docs now point to dump. Verified /Users/alexis/.local/bin/dump help and /Users/alexis/.local/bin/cisco-dump help. Also verified tunnel-aware capture on session 20260331T205351Z: pktap metadata showed traffic on utun9 (Corp/Cisco), utun11 (v2RayTun default path), utun0 (100.100.100.100 route probe), plus en0 and lo0, so the new default capture is not Cisco-only.

## Precondition Resources
(none)

## Outcome Resources
(none)
