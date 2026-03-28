## Status
done

## Assigned To
codex

## Created
2026-03-24T21:59:01Z

## Last Update
2026-03-25T08:41:10Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Current vpn-auth --server full flow reaches SAML+TOTP but fails on ASA error 13 (Cisco Secure Desktop not installed). New plan: let openconnect --authenticate own ASA+CSD, use vpn-auth only as the external-browser automation step, and plumb a CSD wrapper into openconnect runtime.
Implemented openconnect --authenticate as the sole ASA/CSD auth backend. Added a generated --external-browser wrapper that runs vpn-auth --url and replays the localhost callback back into OpenConnect, plus a generated --csd-wrapper around Homebrew csd-post.sh with macOS pidof/stat shims and stable opt/openconnect path resolution. Updated README, SPEC, and LOGBOOK. Verification: go test ./... and go build -o /tmp/openconnect-tun ./cmd/openconnect-tun both pass. Live Corp auth was not rerun in this slice.
If vpn-auth is unavailable, the generated external-browser wrapper now falls back to the system open(1) launcher instead of failing before OpenConnect can present SAML auth.

## Precondition Resources
(none)

## Outcome Resources
(none)
