## Status
to-review

## Assigned To
codex

## Created
2026-04-02T11:32:04Z

## Last Update
2026-04-02T11:32:19Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-04-02 live host state after interrupted openconnect runs: openconnect-tun status reported session: none and Cisco CLI state: disconnected, but /etc/resolver still contained the full Corp split-include resolver set and scutil --dns still exposed corp.example -> 10.23.16.4/10.23.0.23. That stale DNS state is sufficient to break official Cisco AnyConnect SSO navigation on this Mac.
2026-04-02 fix: openconnect Stop now attempts orphaned resolver cleanup even when there is no current session file or only pid=0 stale runtime metadata. Cleanup runs through the shared vpn-core helper when available, removes only resolver files with openconnect-tun ownership headers, and reports cleaned_orphaned / stale_cleaned / cleared_starting_cleaned states in the CLI. Verified with go test ./... and a live ./openconnect-tun stop: /etc/resolver collapsed back to search.tailscale only and scutil --dns no longer showed Corp supplemental resolvers.

## Precondition Resources
(none)

## Outcome Resources
(none)
