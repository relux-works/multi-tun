## Status
development

## Assigned To
codex

## Created
2026-04-01T10:47:10Z

## Last Update
2026-04-01T10:50:01Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-04-01 user live matrix: official AnyConnect-only capture session dump 20260401T103101Z reached portal.corp.example successfully, but dump stop timed out. openconnect-tun-only session dump 20260401T103604Z stopped cleanly, while portal.corp.example did not appear to resolve/reach. Overlay matrix refined behavior further: vless->openconnect order preserved Corp domain resolution but broke unrelated external DNS; openconnect->vless order restored general resolution, while portal remained the separate unresolved domain-classification case. Primary investigation goal: extract exact resolver/IP/route evidence for portal across these stacks and decide whether openconnect should intentionally keep it public or resolve it through Corp DNS.
2026-04-01 13:49 MSK: logged portal dump finding. Official AnyConnect session 20260401T103101Z showed conflicting views inside one session: host-probes-network_change-20260401T103227.970Z.txt resolved/routed portal to 10.25.1.4 via utun5 and timed out, while host-probes-network_change-20260401T103326.093Z.txt resolved/routed it to public 203.0.113.27 via en0 and HTTPS returned 302. Standalone openconnect-tun session 20260401T103604Z stayed on the private 10.25.1.4 view through host-probes-final_stop-20260401T103737.762Z.txt; plain dig still saw public 203.0.113.27, but corporate dig and dscacheutil pinned 10.25.1.4 and HTTPS timed out.

## Precondition Resources
(none)

## Outcome Resources
(none)
