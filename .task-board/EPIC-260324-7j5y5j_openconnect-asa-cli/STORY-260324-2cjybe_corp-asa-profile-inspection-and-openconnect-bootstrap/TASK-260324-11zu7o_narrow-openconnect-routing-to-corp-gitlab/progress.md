## Status
development

## Assigned To
codex

## Created
2026-03-24T19:42:30Z

## Last Update
2026-03-28T17:20:44Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-03-27: starting live smoke of openconnect-tun over active vless-tun, with focus on gitlab.services.corp.example reachability, scoped DNS installation, route selection, and unexpected session artifact accumulation.
2026-03-27: live attempt to start openconnect-tun over active vless-tun reached cookie_obtained but then blocked on local sudo, not on ASA/DNS/routing. Implemented fast-fail before auth/session setup: Connect now checks sudo before SAML/browser flow, prefers cached sudo via sudo -n true, and only falls back to sudo -v when stdin is a real terminal. Added tests for interactive fallback and non-interactive no-artifact failure. Verified with go test ./... and a non-interactive smoke binary run: start now fails immediately with a cached-sudo hint and does not create another openconnect-session-* artifact. True unattended smoke over vless-tun still requires either a warmed sudo timestamp or a future launchd/root helper backend for openconnect-tun.
2026-03-28: narrowed overlay routing reached internal GitLab addresses on 11.x and TCP/22 became reachable over the openconnect utun. Wrapper diagnostics proved unscoped interface routes on utun9 for 11.0.0.0/8 and 11.60.0.177/32. Also fixed probe-host route parsing so dig timeout noise like ;; is filtered out instead of being treated as an address. Fresh live clone smoke is still pending.
2026-03-28 follow-up from user live run: split-include still poisoned general traffic because the connected route table contained a second default route on utun9. The user manually killed openconnect when all domains stopped working. Next fix is to suppress or remove the utun default route during split-include sessions before rerunning GitLab smoke.
2026-03-28 code follow-up: implemented wrapper-side removal of the scoped default route on the openconnect utun during split-include connect and reconnect, alongside the previously added VPNGATEWAY pin route. go test ./... is green and openconnect-tun is rebuilt. Live re-smoke is intentionally pending after the user reported that the previous run poisoned all domains.

## Precondition Resources
(none)

## Outcome Resources
(none)
