## Status
done

## Assigned To
codex

## Created
2026-04-08T14:23:09Z

## Last Update
2026-04-08T14:51:31Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Safe local dynamic check found the v2RayTun app process running but no active listener on ::1:1080 at audit time, indicating the localhost SOCKS listener is session-scoped rather than permanently resident while idle.
Reopened for active-session proof attempt: bring v2RayTun tunnel up and test whether an unrelated local process can connect to ::1:1080 without authentication.
Live proof completed on 2026-04-08. After starting the tunnel from the macOS UI, VPNStatus became 1 and packet-extension-mac listened on [::1]:1080. Raw SOCKS handshake from an unrelated shell process returned 0500 (NO AUTH). An explicit curl via --socks5-hostname [::1]:1080 returned HTTP 200 and response body 144.31.90.46. Tunnel was then stopped and listener disappeared.

## Precondition Resources
(none)

## Outcome Resources
(none)
