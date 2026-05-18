# VLESS TUN Upstream Self-Capture Fix

## Summary

The `fortinetz` full-TUN VLESS session entered a high-CPU `sing-box` storm because traffic to the VLESS upstream server could be captured by the same broad TUN route that `sing-box` installed for client traffic.

Live impact:

- Server/profile: `fortinetz` / `nl`
- Upstream endpoint: `83.222.9.217:443`
- TUN interface: `utun233`
- Observed CPU before fix: roughly `450-500%`
- Observed CPU after restart with fixed config: roughly `0.5-1.8%`

## Root Cause

The renderer produced a full-TUN config without:

- excluding the IP-literal upstream endpoint from `route_exclude_address`
- routing the upstream endpoint through `direct`

That allowed macOS routing to resolve `83.222.9.217` through `utun233`. Under retry-heavy app traffic, `sing-box` churned upstream connections and consumed several logical cores.

OpenConnect was stopped during isolation and the storm continued, so the corporate split tunnel was not the root cause. Telegram produced much of the visible traffic pressure, but it was a trigger, not the durable fault.

## Fix

Implemented in `desktop/internal/vless/singbox/render.go`:

- Detect IP-literal upstream profile hosts.
- Normalize IPv4-mapped IPv6 addresses before deriving endpoint CIDRs.
- Add the endpoint CIDR to TUN `route_exclude_address`.
- Add an inline `upstream-direct` rule set.
- Route `upstream-direct` through the `direct` outbound.
- Merge upstream excludes with overlay DNS / OpenConnect route excludes.
- Skip endpoint route excludes for domain upstream hosts because they do not map to a stable CIDR at render time.

New configs also default `logging.level` to `warn` in `desktop/internal/vless/config/config.go` to avoid normal full-TUN per-connection log noise.

## Validation

Commands:

```bash
go test ./desktop/internal/vless/singbox
go test ./desktop/internal/vless/...
go test ./desktop/...
vless-tun render --server fortinetz --profile nl --output .temp/BUG-260519-1txvh4/rendered-installed-fortinetz.json
sing-box check -c .temp/BUG-260519-1txvh4/rendered-installed-fortinetz.json
```

Rendered config for `fortinetz` / `nl` contains:

```json
{
  "route_exclude_address": ["83.222.9.217/32"],
  "upstream_rule": {
    "action": "route",
    "outbound": "direct",
    "rule_set": ["upstream-direct"]
  }
}
```

Post-restart route check:

```text
route to: 83.222.9.217
gateway: 192.168.1.1
interface: en0
```

This confirms the tunnel server is no longer routed through `utun233`.
