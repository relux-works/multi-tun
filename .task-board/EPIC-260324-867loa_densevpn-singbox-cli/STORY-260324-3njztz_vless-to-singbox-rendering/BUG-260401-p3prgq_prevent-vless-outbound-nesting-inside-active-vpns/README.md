# BUG-260401-p3prgq: prevent-vless-outbound-nesting-inside-active-vpns

## Description
Detect and prevent vless-tun tun mode from routing its upstream VLESS server through another active VPN default route (for example v2RayTun or Cisco AnyConnect), which currently causes nested-tunnel breakage and broad connectivity loss.

## Scope
(define bug scope / affected area)

## Acceptance Criteria
(define fix acceptance criteria)
