# TASK-260324-3248y5: allow-full-tunnel-without-bypasses

## Description
Support empty bypass list so vless-tun can render a simple full-tunnel VLESS config for bring-up

## Scope
- allow `render.bypass_suffixes = []` in config validation
- render a valid sing-box config without direct suffix rules or direct DNS split
- keep the existing suffix-bypass behavior unchanged when bypasses are present
- surface `bypasses: none` in status output for the empty-list case

## Acceptance Criteria
- `go test ./...` passes with coverage for the empty-bypass rendering path
- `vless-tun render` succeeds when `render.bypass_suffixes` is an empty list
- `sing-box check` succeeds for the rendered full-tunnel config
- docs explain that `run` brings the tunnel up and `status` is introspection only
