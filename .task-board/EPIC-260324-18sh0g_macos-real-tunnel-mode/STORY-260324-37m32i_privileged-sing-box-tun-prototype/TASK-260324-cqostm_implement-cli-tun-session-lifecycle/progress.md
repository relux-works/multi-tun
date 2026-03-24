## Status
to-review

## Assigned To
codex

## Created
2026-03-24T12:58:11Z

## Last Update
2026-03-24T18:37:16Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Implemented backend-aware CLI session lifecycle for privileged TUN sessions. vless-tun run/reconnect/status/stop now persist launch metadata, support launchd-managed sing-box sessions, and report launch_mode alongside PID/session state. go test ./... passes.

## Precondition Resources
(none)

## Outcome Resources
(none)
