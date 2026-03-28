## Status
to-review

## Assigned To
codex

## Created
2026-03-28T10:20:09Z

## Last Update
2026-03-28T11:21:20Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-03-28 shipped slice: extracted shared vpn-core service/rpc/process modules and vpn-core CLI; openconnect helper now wraps the shared core; vless tun mode now prefers helper/vpn-core for privileged sing-box spawn and stop; vpn-core status and openconnect-tun helper status auto-detect the legacy works.relux.openconnect-tun-helper install so already trusted helpers continue to work during migration; go test ./... passed and live status on this machine resolves the legacy helper as reachable.
2026-03-28 follow-up fix: legacy launchd-managed vless sessions keep a working stop path during migration, so existing root sing-box sessions can be stopped cleanly before the next helper-backed start.
2026-03-28 live validation: vpn-core reachable, legacy vless launchd session stopped cleanly, and a new vless session came up in helper mode with utun233 present. Shared core migration is now proven on both status and real vless bring-up paths.

## Precondition Resources
(none)

## Outcome Resources
(none)
