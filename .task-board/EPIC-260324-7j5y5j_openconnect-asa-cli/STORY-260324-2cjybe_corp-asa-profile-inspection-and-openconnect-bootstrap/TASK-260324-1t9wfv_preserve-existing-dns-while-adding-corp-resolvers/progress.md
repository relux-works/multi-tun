## Status
development

## Assigned To
codex

## Created
2026-03-24T19:42:05Z

## Last Update
2026-03-28T19:45:39Z

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
2026-03-28 live finding: split-include openconnect still pollutes global macOS DNS state. Session 20260328T185257Z applied scutil SearchDomains + SupplementalMatchDomains for broad Corp suffix set, and scutil --dns showed resolver #1 search domains expanded with corp.example/inside.corp.example/region.corp.example/... alongside IGD_MGTS. Overlay result: openconnect alone resolves GitLab but regular domains get slow/odd; vless-tun started above openconnect keeps dns-direct as local DHCP on en0 (see sing-box-session-20260328T185549Z: updated DNS servers from en0 [192.168.1.1:53], search [IGD_MGTS]) and does not take resolver ownership. v2raytun reportedly does take over DNS correctly above the same openconnect session. Next slice: stop global DNS pollution from openconnect split-include first, then revisit vless DNS takeover semantics.
2026-03-28 implementation update: split-include no longer uses openconnect-tun-owned scutil DNS state or search.tailscale sanitation. supplementalResolverSpecForConnect now keeps split mode on per-domain resolver files + host/route overrides only, which removes the code path that injected broad Corp SearchDomains/SupplementalMatchDomains into global macOS resolver state. Coverage updated in internal/openconnect/runtime_test.go and go test ./... passed. Remaining gap: no fresh live smoke yet, and vless overlay still needs a separate fix because current sing-box dns-direct path continues to bind to DHCP DNS from en0 rather than consuming openconnect supplemental resolver state.
2026-03-28 live confirmation: updated split-include build was smoked again and openconnect came up cleanly without poisoning the main resolver stack. User reported GitLab kept working and primary DNS stayed intact; Corp DNS behavior looked like an extension rather than a takeover. This validates the scutil/search-domain removal for standalone openconnect. Overlay with vless-tun is still a separate unresolved DNS ownership issue.

## Precondition Resources
(none)

## Outcome Resources
(none)
