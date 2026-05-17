#!/bin/sh
set -eu

profile="${1:-nl}"
root_dir="$(cd "$(dirname "$0")/../../.." && pwd)"
tmp_dir="$root_dir/.temp/fortinetz-cascade/sni-lab"
rendered="$tmp_dir/rendered-$profile.json"
runtime="$tmp_dir/sing-box-tun-$profile.json"
out_base="$tmp_dir/results-$profile"

mkdir -p "$tmp_dir" "$out_base"

vless-tun render --server fortinetz --profile "$profile" --output "$rendered" >/dev/null

jq '
  .inbounds = [{
    "type": "mixed",
    "tag": "mixed-in",
    "listen": "127.0.0.1",
    "listen_port": 1080,
    "sniff": true
  }]
  | .route.rule_set = ((.route.rule_set // []) | map(select(.tag != "ru-direct")))
  | .route.rules = ((.route.rules // []) | map(select(((.rule_set // []) | index("ru-direct")) | not)))
  | .dns.rules = ((.dns.rules // []) | map(select(((.rule_set // []) | index("ru-direct")) | not)))
  | (.outbounds[] | select(.tag == "proxy")) += {"detour": "sni-gate"}
  | .outbounds += [{
    "type": "socks",
    "tag": "sni-gate",
    "server": "127.0.0.1",
    "server_port": 18080,
    "version": "5"
  }]
' "$rendered" > "$runtime"

"$root_dir/artifacts/fortinetz-cascade-whitelist/lab/run-docker-sni-matrix.sh" "$runtime" "$out_base"
