# TunWave (`tun-wave`) — Workspace Instructions

- **Axiloom Board:** `TunWave` (`tun-wave`, `proj_cekgqm644n6agzx4q63hyyd5tu`), bound via local `.axiloom.json` (gitignored).
- **Lead Role Profile:** `tech-lead (ap-role-tech-lead)` supervised under `archon-sanctuary` (see `LAUNCH.md` for launch runbook).
- **Orientation:** Run `axiloom guide --with-status`, `axiloom validate --strict`, and `archon-sanctuary guide` at session start.
- **Sibling Repo:** `/Users/alexis/src/vless-tun`.
- **CRITICAL SAFETY RULE:** NEVER test, restart, or mutate VPN/TUN tunnels (`utun*`, `sing-box`, `multi-tun`, `vless-tun`) on this primary Mac (`m1max`). All live tunnel tests MUST run on `work-mac` over SSH after stopping all Claude/Codex sessions on `work-mac`.
