# Fortinetz Cascade And Whitelist Bypass Check

Date: 2026-05-17

## Scope

This report checks the provider claim that Fortinetz profiles use default cascade-style tunneling for whitelist bypass. The goal was to separate facts visible from the client from claims that require provider-side visibility or a real restricted network.

The live client was `vless-tun` in TUN mode with Fortinetz profiles imported into `~/.config/vless-tun/config.json`.

## Method

1. Render each Fortinetz profile and extract the client-visible outbound shape from the generated sing-box config.
2. Reconnect each profile and query `https://api.ipify.org`, then enrich the result through `ipinfo.io`.
3. Use `vpn-core` to run privileged `tcpdump` on `en0` and capture the first-hop TLS ClientHello to `83.222.9.217:443`.
4. Compare configured Reality `server_name` values against the SNI strings visible in packet captures.
5. Check whether local `.ru` / `.рф` bypasses could invalidate the probes.
6. Attempt a route-based first-hop block as a negative control, then classify whether that method is valid.

Raw logs and temporary captures are under:

- `.temp/fortinetz-cascade/`

## Rendered First-Hop Matrix

All Fortinetz profiles use the same first-hop server IP and port:

| Profile | Protocol | First hop | Reality mask / SNI | uTLS | Reality |
| --- | --- | --- | --- | --- | --- |
| `nl` | VLESS TCP | `83.222.9.217:443` | `www.amazon.com` | `chrome` | enabled |
| `fi` | VLESS TCP | `83.222.9.217:443` | `www.bing.com` | `chrome` | enabled |
| `tr` | VLESS TCP | `83.222.9.217:443` | `www.microsoft.com` | `chrome` | enabled |
| `de` | VLESS TCP | `83.222.9.217:443` | `www.cloudflare.com` | `chrome` | enabled |
| `us` | VLESS TCP | `83.222.9.217:443` | `www.apple.com` | `chrome` | enabled |

Entry IP enrichment:

| IP | Country | Region | ASN / org |
| --- | --- | --- | --- |
| `83.222.9.217` | RU | St.-Petersburg | `AS9123 JSC TIMEWEB` |

Evidence:

- `.temp/fortinetz-cascade/profile-outbound-matrix-01.tsv`
- `.temp/fortinetz-cascade/entry-ipinfo-83.222.9.217-01.json`

## Packet Capture Result

`tcpdump` was launched through `vpn-core` as root, capturing packets on `en0` for `host 83.222.9.217 and tcp port 443`.

Packet captures confirmed that the first-hop ClientHello exposes the configured mask names:

| Profile | Expected SNI | Capture result |
| --- | --- | --- |
| `nl` | `www.amazon.com` | seen |
| `fi` | `www.bing.com` | seen |
| `tr` | `www.microsoft.com` | seen in fresh stop/start capture |
| `de` | `www.cloudflare.com` | seen |
| `us` | `www.apple.com` | seen |

The first `tr` reconnect capture saw `www.amazon.com` because it caught an old `nl` connection during reconnect. A fresh stop -> capture -> start sequence corrected the result and showed `www.microsoft.com`.

Evidence:

- `.temp/fortinetz-cascade/profile-sni-pcap-matrix-01.tsv`
- `.temp/fortinetz-cascade/entry-en0-tr-fresh-strings-02.txt`
- `.temp/fortinetz-cascade/entry-en0-nl-01.pcap`
- `.temp/fortinetz-cascade/entry-en0-fi-01.pcap`
- `.temp/fortinetz-cascade/entry-en0-tr-fresh-02.pcap`
- `.temp/fortinetz-cascade/entry-en0-de-01.pcap`
- `.temp/fortinetz-cascade/entry-en0-us-01.pcap`

## Egress Matrix

Each profile produced a different final egress IP and expected country, while all profiles used the same first-hop IP.

| Profile | Egress IP | Country | ASN / org |
| --- | --- | --- | --- |
| `nl` | `185.11.135.250` | NL | `AS210976 Timeweb, LLP` |
| `fi` | `91.184.243.246` | FI | `AS210644 AEZA GROUP LLC` |
| `tr` | `194.87.246.211` | TR | `AS207483 Netvia Bilisim Yazilim Dan. Tic. Ltd. Sti.` |
| `de` | `94.156.155.48` | DE | `AS207957 SERV.HOST GROUP LTD` |
| `us` | `31.44.6.12` | US | `AS208951 ITGLOBAL.COM` |

Evidence:

- `.temp/fortinetz-cascade/profile-egress-matrix-01.tsv`

## Local Bypass Control

The live local routing config has `.ru` and `.рф` suffix bypasses. These bypasses can invalidate whitelist simulation if the test target matches them.

The egress probes used `api.ipify.org` and `ipinfo.io`, which do not match the local `.ru` / `.рф` bypass suffixes. Those probes therefore tested the tunnel path, not the local direct bypass path.

For any future `.ru` / `.рф` whitelist simulation, use one of these controls:

- temporarily render a clean-routing profile with empty `bypass_suffixes`, `bypass_exclude_suffixes`, and `routes`
- or use only test targets that cannot match local direct bypasses

## Invalid Negative Control

I attempted to block the first-hop IP by adding a temporary route:

```text
route add -host 83.222.9.217 127.0.0.1
```

The route was added through `vpn-core`, verified before startup, and deleted after the test.

Result:

- before tunnel start, `route get 83.222.9.217` pointed to `127.0.0.1` / `lo0`
- `vless-tun start --server fortinetz --profile nl` still started successfully
- `api.ipify.org` still returned the Fortinetz NL egress IP

Conclusion:

This is not a valid firewall emulator for `vless-tun`. The sing-box TUN bring-up and/or protected outbound socket handling can bypass or replace this route-level control. Packet capture still confirmed that the real first-hop traffic leaves on `en0`, but a route-only block is not a reliable way to emulate whitelist filtering here.

Evidence:

- `.temp/fortinetz-cascade/entry-ip-block-negative-control-01.log`
- `.temp/fortinetz-cascade/blocked-route-session-focused-01.log`

## What Was Proven

1. Fortinetz profiles use one common visible entry IP: `83.222.9.217:443`.
2. The entry IP is in Russia (`AS9123 JSC TIMEWEB`).
3. The client-visible first hop uses VLESS Reality over TCP with different popular-site SNI masks per profile.
4. The configured SNI masks were confirmed in real packet captures on `en0`.
5. The selected profile changes the final observed egress IP/country/ASN.
6. The final egress IPs differ from the common first-hop IP, which is strong evidence of provider-side backend routing after the Reality entry.

## What Was Not Proven

1. The full internal provider path was not traced. Once traffic enters the VLESS/Reality server, client-side traceroute cannot reveal provider-side hops.
2. A multi-hop cascade chain was not proven. The evidence supports entry-to-exit separation and profile-controlled provider-side routing, but not the exact number of provider hops.
3. Real Russian whitelist bypass was not proven locally. That requires either a real restricted network or a controlled DPI/SNI whitelist emulator.

## Whitelist Bypass Assessment

The claim depends on what the whitelist filter actually checks.

If the filter is a strict `.ru` / `.рф` SNI/domain whitelist, the current Fortinetz masks should fail:

- `www.amazon.com`
- `www.bing.com`
- `www.microsoft.com`
- `www.cloudflare.com`
- `www.apple.com`

These are not `.ru` / `.рф` names.

If the filter allows popular western SNI values or only checks for a browser-like TLS ClientHello without validating destination IP reputation, Fortinetz has a plausible camouflage path. Packet captures confirm that the client sends these popular-site SNI masks on the first hop.

If the filter blocks the entry IP `83.222.9.217`, client-side camouflage cannot prove bypass by itself. A real firewall/DPI test is needed.

## Colima SNI Gate Lab

Colima can host a safer Linux lab for this, but the lab should not be a route-only block. Docker/Colima networking does not reproduce macOS `utun` and protected socket behavior exactly, and the route-only test already produced an invalid result on macOS.

The useful Colima lab is a DPI/SNI gateway. The first implementation attempted container-local `iptables` `REDIRECT` of root-owned TCP/443 sockets into a local gate. The rule counter incremented, but Docker/Colima did not deliver the redirected connection to the userspace listener reliably. The working lab therefore uses an explicit local SOCKS5 detour:

1. Render the Fortinetz profile locally.
2. Convert the runtime config to a local `mixed` inbound on `127.0.0.1:1080`.
3. Remove the `ru-direct` rule-set from the lab runtime config so suffix bypasses cannot produce false positives.
4. Add a sing-box SOCKS outbound tagged `sni-gate`.
5. Set the Fortinetz VLESS outbound to dial through `sni-gate`, preserving the real requested first hop `83.222.9.217:443`.
6. The Python gate accepts the SOCKS5 CONNECT, reads the Reality TLS ClientHello, extracts SNI, applies the policy, and either proxies the connection or closes it.

The lab runs on the dedicated Mac mini over SSH, not on the local workstation, so it does not stop or disturb the local `vless-tun` session that Codex depends on:

```bash
artifacts/fortinetz-cascade-whitelist/lab/run-macmini-sni-lab.sh nl
```

Remote execution uses:

- SSH target: `relux-works-dedicated-macmini`
- isolated Colima profile: `fortinetz-sni-lab`
- Docker socket: `/Users/administrator/.colima/fortinetz-sni-lab/docker.sock`
- remote scratch dir: `/Users/administrator/.cache/multi-tun/fortinetz-sni-lab`
- local result dir: `.temp/fortinetz-cascade/sni-lab-remote/results-<profile>/`

Existing remote Colima profiles `default` and `coolify` were left running and untouched. The runner uses `--activate=false` and an explicit `DOCKER_HOST` so it does not steal the remote user's active Docker context.

Remote lab safety notes:

- The local workstation `vless-tun` session is never stopped by the remote runner.
- The local workstation is only the control plane: it renders a temporary clean lab config, syncs lab files over SSH, and copies results back.
- The Mac mini keeps the lab in a dedicated Colima profile named `fortinetz-sni-lab`.
- The runner uses explicit `DOCKER_HOST=unix:///Users/administrator/.colima/fortinetz-sni-lab/docker.sock`.
- Existing remote Docker/Colima workloads were not restarted, stopped, or reconfigured.
- The lab containers are disposable and are removed after each policy run.

Policies to test:

| Policy | Emulator behavior | Expected Fortinetz result |
| --- | --- | --- |
| `strict_ru_sni` | allow only SNI ending in `.ru` or `.xn--p1ai` | fail |
| `popular_sni_allow` | allow configured masks such as `www.amazon.com` / `www.bing.com` | pass |
| `sni_ip_match` | allow only if SNI resolves to the original destination IP | fail |
| `entry_ip_block` | block destination `83.222.9.217:443` | fail |

Interpretation:

- Passing `popular_sni_allow` proves the camouflage works against a loose SNI-only allowlist.
- Failing `strict_ru_sni` means the provider does not bypass a real `.ru` / `.рф`-only whitelist with the current masks.
- Failing `sni_ip_match` means the camouflage does not survive a DPI that validates SNI against destination IP reputation.
- Passing any strict policy would be surprising and should trigger packet-capture validation, because it may mean the emulator is not actually intercepting the first-hop connection.

## SNI Gate Matrix

The controlled lab results matched the expected boundaries:

| Profile | SNI seen by gate | Popular-SNI policy | Popular-SNI egress | Strict `.ru` SNI | SNI/IP match | Entry IP block |
| --- | --- | --- | --- | --- | --- | --- |
| `nl` | `www.amazon.com` | pass | `185.11.135.250` | fail | fail | fail |
| `fi` | `www.bing.com` | pass | `91.184.243.246` | fail | fail | fail |
| `tr` | `www.microsoft.com` | pass | `194.87.246.211` | fail | fail | fail |
| `de` | `www.cloudflare.com` | pass | `94.156.155.48` | fail | fail | fail |
| `us` | `www.apple.com` | pass | `31.44.6.12` | fail | fail | fail |

Evidence:

- `.temp/fortinetz-cascade/remote-sni-lab-run-nl-04.log`
- `.temp/fortinetz-cascade/remote-sni-lab-run-cross-profiles-01.log`
- `.temp/fortinetz-cascade/remote-sni-lab-run-us-retry-01.log`
- `.temp/fortinetz-cascade/sni-lab-remote/results-nl/matrix.tsv`
- `.temp/fortinetz-cascade/sni-lab-remote/results-fi/matrix.tsv`
- `.temp/fortinetz-cascade/sni-lab-remote/results-tr/matrix.tsv`
- `.temp/fortinetz-cascade/sni-lab-remote/results-de/matrix.tsv`
- `.temp/fortinetz-cascade/sni-lab-remote/results-us/matrix.tsv`

## Verdict

Fortinetz does have real client-visible camouflage: VLESS Reality over TCP to a Russian entry IP with popular-site SNI masks, confirmed by packet capture.

Fortinetz also appears to do provider-side routing from one common entry IP to different country-specific exits. That is enough to say the client enters one Fortinetz edge and the provider selects a backend/exit per profile.

The stronger marketing claim, "default cascade tunnels bypass whitelists," is only partially supported by local evidence. We can support "camouflaged entry plus provider-side exit routing." The controlled emulator shows that Fortinetz passes a loose allowlist that accepts the configured popular SNI masks, but fails a strict `.ru` / `.рф` SNI whitelist, an SNI-to-entry-IP validation policy, and a direct block of the entry IP.

What remains unproven is the internal provider hop count and behavior on a real Russian restricted network. Those require provider-side visibility or a real external network condition, not just client-side traces.

## Short Summary

Fortinetz uses real client-visible camouflage: all tested profiles connect first to `83.222.9.217:443` in Russia using VLESS Reality with popular-site SNI masks.

The selected profile changes the final exit country, so the evidence supports provider-side entry-to-exit routing after the common Reality entry.

The controlled SNI-gate emulator shows the boundary clearly: Fortinetz works if a network allows the configured popular SNI masks, but it fails a strict `.ru` / `.рф` SNI whitelist, SNI-to-IP validation, and direct blocking of the entry IP.

Bottom line: "camouflaged entry plus provider-side exit routing" is supported. "Default cascade tunnels bypass strict whitelists" is not proven and does not hold against the strict policies tested here.
