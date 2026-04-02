## Status
to-review

## Assigned To
codex

## Created
2026-04-02T10:53:40Z

## Last Update
2026-04-02T11:24:01Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
2026-04-02 repro from user: openconnect-tun start prints auth_stage fetching_saml_config and then stalls before surfacing any SSO login URL. Fresh session log stops after aggregate_auth_init_url: https://vpn-gw2.corp.example/outside, so the hang happens during or before the initial aggregate-auth POST response is read.
2026-04-02 follow-up with active vless overlay: the host already had broad bypasses (.ru/.рф), but sing-box overlay DNS still sent corp.example matches to dns-overlay before bypass evaluation. That made vpn-gw2.corp.example resolve on the corporate overlay path despite bypass intent. Fix applied in internal/singbox render so tun-mode bypass DNS wins before overlay routing, and local ~/.config/openconnect-tun/config.json now also lists vpn-gw2.corp.example under the active openconnect bypass_suffixes overrides.
2026-04-02 hostscan follow-up: fresh session 20260402T111926Z progressed past fetching_saml_config into aggregate_auth_hostscan but then stalled before any csd wrapper output. Root cause in code: native libcsd config still fetched the server cert hash via tls.Dial(hostname:443), which used the old system resolver path and could hang on vpn-gw2.corp.example under the pre-VPN corp.example supplemental DNS. That silently forced aggregate hostscan back to csd-post.sh because prepareCSDWrapper discarded the native error. Fix: fetchServerCertSHA1 now resolves through resolveOpenConnectDialAddress before TLS dial, and hostscan logs native fallback reasons via hostscan_csd_native_unavailable. Verified with go test ./... and rebuilt ./openconnect-tun.

## Precondition Resources
(none)

## Outcome Resources
(none)
