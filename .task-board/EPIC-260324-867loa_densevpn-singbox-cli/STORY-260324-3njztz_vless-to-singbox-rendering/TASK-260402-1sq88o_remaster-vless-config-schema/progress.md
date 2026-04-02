## Status
done

## Assigned To
codex

## Created
2026-04-02T13:32:05Z

## Last Update
2026-04-02T14:07:09Z

## Blocked By
- (none)

## Blocks
- TASK-260402-2rezbl

## Checklist
- [x] Map the current vless-tun config semantics in code and live JSON
- [x] Define a cleaner target schema with clear separation between selection, runtime, launch, and render policy
- [x] Migrate loader/runtime to the new preferred schema with backward compatibility
- [x] Cover the new schema in tests and migrate the live config
- [x] Replace subscription_url with source.mode + source.url in the preferred schema
- [x] Make launch override-only and implicit in the happy path when vpn-core is available
- [x] Rename the generated sing-box artifact path to a provider-neutral singbox_config_path

## Notes
Current smell: ProjectConfig is shallow at the root, but render carries mode, output path, TUN/proxy transport, bypass policy, proxy DNS, and privileged launch. We want a cleaner boundary so render-only fields stop acting as the home for unrelated operational concerns.
Current agreed direction: replace the misleading subscription_url field with a source block. Preferred shape should support source.mode=proxy|direct, where proxy means an HTTP source URL that resolves to one or more VLESS URIs, and direct means a literal VLESS source URI with no extra fetch indirection. This keeps the config honest for both DanceVPN-style subscription gateways and single-VPS direct setups.
Current agreed direction: replace the misleading subscription_url field with a source block. Preferred shape should support source.mode=proxy|direct, where proxy means an HTTP source URL that resolves to one or more VLESS URIs, and direct means a literal VLESS source URI with no extra fetch indirection. This keeps the config honest for both DanceVPN-style subscription gateways and single-VPS direct setups.
Launch policy direction: launch should be treated as an override, not as a required happy-path config block. If launch is omitted, vless-tun should behave like openconnect-tun and default to the shared vpn-core backend when available, with existing auto fallback behavior under the hood. Exposed launch fields should remain only for explicit override/debug/fallback cases.
Current smell: ProjectConfig is shallow at the root, but render carries mode, output path, TUN/proxy transport, bypass policy, proxy DNS, and privileged launch. We want a cleaner boundary so render-only fields stop acting as the home for unrelated operational concerns.
Current agreed direction: replace the misleading subscription_url field with a source block. Preferred shape should support source.mode=proxy|direct, where proxy means an HTTP source URL that resolves to one or more VLESS URIs, and direct means a literal VLESS source URI with no extra fetch indirection. This keeps the config honest for both DanceVPN-style subscription gateways and single-VPS direct setups.
Launch policy direction: launch should be treated as an override, not as a required happy-path config block. If launch is omitted, vless-tun should behave like openconnect-tun and default to the shared vpn-core backend when available, with existing auto fallback behavior under the hood. Exposed launch fields should remain only for explicit override/debug/fallback cases.
Target shape direction: keep cache_dir at the root, add source + default blocks, split network concerns by mode, keep routing and dns policy separate, keep logging separate, and rename the generated sing-box artifact to a neutral singbox_config_path with a generic generated filename such as sing-box.json rather than a provider-specific name.
Current smell: ProjectConfig is shallow at the root, but render carries mode, output path, TUN/proxy transport, bypass policy, proxy DNS, and privileged launch. We want a cleaner boundary so render-only fields stop acting as the home for unrelated operational concerns.
Current agreed direction: replace the misleading subscription_url field with a source block. Preferred shape should support source.mode=proxy|direct, where proxy means an HTTP source URL that resolves to one or more VLESS URIs, and direct means a literal VLESS source URI with no extra fetch indirection. This keeps the config honest for both DanceVPN-style subscription gateways and single-VPS direct setups.
Launch policy direction: launch should be treated as an override, not as a required happy-path config block. If launch is omitted, vless-tun should behave like openconnect-tun and default to the shared vpn-core backend when available, with existing auto fallback behavior under the hood. Exposed launch fields should remain only for explicit override/debug/fallback cases.
Target shape direction: keep cache_dir at the root, add source + default blocks, split network concerns by mode, keep routing and dns policy separate, keep logging separate, and rename the generated sing-box artifact to a neutral singbox_config_path with a generic generated filename such as sing-box.json rather than a provider-specific name.
Implemented: internal/config/config.go now supports the new preferred source/default/network/launch/routing/dns/logging/artifacts schema with fallback to legacy subscription_url/render fields; direct VLESS sources are supported through source.mode=direct; live ~/.config/vless-tun/config.json was migrated to the preferred shape; go test ./... passed and ./vless-tun was rebuilt.

## Precondition Resources
(none)

## Outcome Resources
(none)
