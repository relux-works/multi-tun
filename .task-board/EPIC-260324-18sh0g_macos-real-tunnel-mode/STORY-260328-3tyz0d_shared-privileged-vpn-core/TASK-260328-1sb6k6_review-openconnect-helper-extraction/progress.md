## Status
to-review

## Assigned To
codex

## Created
2026-03-28T10:20:21Z

## Last Update
2026-03-28T10:52:02Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-03-28 review findings:
1. openconnect helper already centralizes one-time root trust, launchd bootstrap, unix socket RPC, privileged process spawn, and privileged signal handling in internal/openconnect/helper.go.
2. The extracted primitive set is already broader than openconnect: helper connect accepts an argv payload + stdin cookie + log path, and helper signal can send kill signals to arbitrary PIDs. That means the real core is generic, but the API surface is still named and packaged as openconnect-specific.
3. vless-tun still duplicates privileged lifecycle separately in internal/session/launchd.go and internal/session/session.go: plist install, launchctl bootstrap/bootout, PID lookup, and stop logic all sit outside the helper model and still require sudo per command.
4. Live operational gap confirmed: the root launchd-managed sing-box service can keep routing state active even when the non-root CLI cannot stop or reconfigure it autonomously. This is exactly the class of problem the helper/core should absorb.
5. Current helper API is too generic/unsafe for a long-term shared core: Action=connect accepts arbitrary command argv, and Action=signal can kill arbitrary root PIDs. For a shared VPN core we should tighten this into typed primitives or scoped session handles, not a generic root command runner.
6. The file/module split is not ready yet: helper install/bootstrap, socket RPC client, daemon loop, request handlers, and plist rendering are all mixed in one file today. vless-tun launchd code has a similar mix of privileged transport and protocol-specific lifecycle.

## Precondition Resources
(none)

## Outcome Resources
(none)
