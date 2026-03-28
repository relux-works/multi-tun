## Status
development

## Assigned To
codex

## Created
2026-03-24T19:42:05Z

## Last Update
2026-03-24T19:58:24Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Starting DNS preservation investigation. Goal: keep existing resolver stack (for example vless-tun) and add only scoped Corp resolvers instead of replacing DNS globally.
Confirmed the DNS preservation direction. Stock vpnc-script on this machine mutates global DNS via scutil/networksetup, but vpn-slice on macOS implements split DNS through scoped /etc/resolver/<domain> files. That makes split-include + vpn-slice the candidate path for preserving the existing default resolver stack while adding Corp-only DNS.

## Precondition Resources
(none)

## Outcome Resources
(none)
