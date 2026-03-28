## Status
development

## Assigned To
codex

## Created
2026-03-24T19:42:05Z

## Last Update
2026-03-28T12:10:54Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Starting DNS preservation investigation. Goal: keep existing resolver stack (for example vless-tun) and add only scoped Corp resolvers instead of replacing DNS globally.
Confirmed the DNS preservation direction. Stock vpnc-script on this machine mutates global DNS via scutil/networksetup, but vpn-slice on macOS implements split DNS through scoped /etc/resolver/<domain> files. That makes split-include + vpn-slice the candidate path for preserving the existing default resolver stack while adding Corp-only DNS.
2026-03-28: live overlay smoke kept the existing vless default path working while openconnect added Corp-scoped resolvers and routes. curl https://www.avito.ru/ still completed with HTTP/2 403 during the session, which is enough evidence that non-Corp traffic was not globally blackholed by the DNS changes.

## Precondition Resources
(none)

## Outcome Resources
(none)
