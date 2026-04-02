## Status
to-review

## Assigned To
codex

## Created
2026-04-01T08:14:32Z

## Last Update
2026-04-01T08:19:20Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Implemented legacy launchd fallback for vless-tun current-session resolution in internal/session/session.go, wired it into internal/cli/status.go, internal/cli/diagnose.go, and internal/cli/run_stop.go, and made launchd read-only inspection use plain launchctl print before sudo fallback so normal users can detect system/works.relux.vless-tun. Added unit coverage in internal/session/session_test.go for ResolveCurrent legacy metadata recovery and Stop without current-session.json. Verified live on host after rebuilding vless-tun: status/diagnose now report session=active pid=570 launch_mode=launchd for the orphaned works.relux.vless-tun service, and stop now enters the privileged stop path instead of returning no current session file found. Remaining manual admin step: run vless-tun stop interactively with sudo password and remove /Library/LaunchDaemons/works.relux.vless-tun.plist once.

## Precondition Resources
(none)

## Outcome Resources
(none)
