## Status
development

## Assigned To
codex

## Created
2026-03-24T19:42:30Z

## Last Update
2026-03-27T15:32:57Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-03-27: starting live smoke of openconnect-tun over active vless-tun, with focus on gitlab.services.corp.example reachability, scoped DNS installation, route selection, and unexpected session artifact accumulation.
2026-03-27: live attempt to start openconnect-tun over active vless-tun reached cookie_obtained but then blocked on local sudo, not on ASA/DNS/routing. Implemented fast-fail before auth/session setup: Connect now checks sudo before SAML/browser flow, prefers cached sudo via sudo -n true, and only falls back to sudo -v when stdin is a real terminal. Added tests for interactive fallback and non-interactive no-artifact failure. Verified with go test ./... and a non-interactive smoke binary run: start now fails immediately with a cached-sudo hint and does not create another openconnect-session-* artifact. True unattended smoke over vless-tun still requires either a warmed sudo timestamp or a future launchd/root helper backend for openconnect-tun.

## Precondition Resources
(none)

## Outcome Resources
(none)
