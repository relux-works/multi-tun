#!/bin/sh
set -eu

profile="${1:-nl}"
remote="${FORTINETZ_SNI_LAB_REMOTE:-relux-works-dedicated-macmini}"
remote_profile="${FORTINETZ_SNI_LAB_COLIMA_PROFILE:-fortinetz-sni-lab}"
remote_dir="${FORTINETZ_SNI_LAB_REMOTE_DIR:-/Users/administrator/.cache/multi-tun/fortinetz-sni-lab}"
root_dir="$(cd "$(dirname "$0")/../../.." && pwd)"
local_tmp="$root_dir/.temp/fortinetz-cascade/sni-lab-remote"
rendered="$local_tmp/rendered-$profile.json"
runtime="$local_tmp/sing-box-socks-$profile.json"
out_base="$local_tmp/results-$profile"
remote_sock="/Users/administrator/.colima/$remote_profile/docker.sock"

mkdir -p "$local_tmp" "$out_base"

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

ssh "$remote" \
  "PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin; set -eu; \
   if ! command -v colima >/dev/null 2>&1 || ! command -v docker >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then \
     if ! command -v brew >/dev/null 2>&1; then echo 'Homebrew is required to install colima/docker/jq' >&2; exit 1; fi; \
     brew install colima docker jq; \
   fi; \
   mkdir -p '$remote_dir/lab' '$remote_dir/work' '$remote_dir/results-$profile'; \
   previous_context=\"\$(docker context show 2>/dev/null || true)\"; \
   if ! colima list 2>/dev/null | awk -v p='$remote_profile' '\$1 == p && \$2 == \"Running\" { found = 1 } END { exit found ? 0 : 1 }'; then \
     colima start '$remote_profile' --activate=false --runtime docker --cpu 2 --memory 2 --disk 20 --mount none; \
   fi; \
   if [ -n \"\$previous_context\" ]; then docker context use \"\$previous_context\" >/dev/null 2>&1 || true; fi; \
   test -S '$remote_sock'"

rsync -az --delete --exclude __pycache__ \
  "$root_dir/artifacts/fortinetz-cascade-whitelist/lab/" \
  "$remote:$remote_dir/lab/"
rsync -az "$runtime" "$remote:$remote_dir/work/sing-box.json"

ssh "$remote" \
  "PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin; set -eu; \
   chmod +x '$remote_dir/lab/run-docker-sni-matrix.sh' '$remote_dir/lab/run-policy.sh' '$remote_dir/lab/sni-gate.py'; \
   DOCKER_HOST='unix://$remote_sock' '$remote_dir/lab/run-docker-sni-matrix.sh' '$remote_dir/work/sing-box.json' '$remote_dir/results-$profile' > '$remote_dir/results-$profile/remote-run.log' 2>&1"

rm -rf "$out_base"
mkdir -p "$out_base"
rsync -az "$remote:$remote_dir/results-$profile/" "$out_base/"
cat "$out_base/matrix.tsv"
