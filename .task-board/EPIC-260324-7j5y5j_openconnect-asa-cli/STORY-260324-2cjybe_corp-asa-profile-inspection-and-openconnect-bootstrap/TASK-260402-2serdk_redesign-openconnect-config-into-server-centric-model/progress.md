## Status
to-review

## Assigned To
codex

## Created
2026-04-02T12:24:16Z

## Last Update
2026-04-02T13:14:19Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Implement schema support for default.server_url and default.profile plus servers.<url>.profiles.<profile>
- [x] Move mode and split_include ownership to the profile level in option resolution
- [x] Remove reliance on duplicated root split_include and default_mode for the remastered path
- [x] Update tests and normalize vpn_domains as suffix masks without redundant covered entries

## Notes
Current config model feels smeared across top-level servers and profiles. The real connect target is still resolved implicitly from AnyConnect XML when only a profile selector is given, so config readers do not see an explicit profile-to-server relationship in JSON. Redesign goal: make server the primary unit and make selector/profile attachment explicit instead of indirect.
Design direction refined from discussion: split_include policy should likely live on the profile selector rather than on the server, because different user-facing profiles may intentionally carry different routing and bypass behavior even when they ultimately connect to the same ASA endpoint. The server object should stay as the explicit transport target and home for truly shared endpoint-level defaults, while each profile points to a server explicitly and owns its split_include policy.
Another concrete smell from the live config: the top-level split_include block currently carries obviously endpoint-specific data such as private corp routes (10/8, 11/8, 172.16/12, 192.168/16), Corp resolver IPs, and corp.example DNS policy. In practice that reads like server or profile policy, not like a true global default shared across unrelated VPN targets. Redesign should avoid that overlap and make the ownership of split_include explicit.
Live config cleanup applied on 2026-04-02 while reviewing the target schema: removed the root-level split_include block from ~/.config/openconnect-tun/config.json because it duplicated Corp-specific routes, DNS servers, and vpn_domains that already belong to concrete profile/server policy rather than true global defaults.
Working target schema agreed during live config review on 2026-04-02: cache_dir at root, default.server_url and default.profile for the default selection, servers keyed by connect URL, and profiles nested inside each server. Each profile owns mode plus split_include policy. Do not reintroduce a root split_include block unless a truly shared cross-server default appears later. Keep vpn_domains documented and treated as suffix masks, so corp.example already covers inside.corp.example and region.corp.example.
Implementation shipped on 2026-04-02. openconnectcfg now supports the remastered schema with default.server_url plus default.profile at the root and nested servers.<url>.profiles.<profile>.mode plus split_include. parseRunOptions now resolves defaults from the new block, resolves configured server URLs from nested profile entries before falling back to AnyConnect XML, and prefers profile mode over legacy default_mode. Domain normalization now treats vpn_domains as suffix masks and collapses redundant covered entries such as inside.corp.example under corp.example. Added regression coverage in internal/openconnectcfg/config_test.go and internal/openconnectcli/app_test.go. Verified with go test ./internal/openconnectcfg ./internal/openconnectcli, go test ./..., and rebuilt ./openconnect-tun. Live ~/.config/openconnect-tun/config.json was migrated from the mixed legacy plus draft state to the new single-shape config.

## Precondition Resources
(none)

## Outcome Resources
(none)
