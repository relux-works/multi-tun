# TASK-260402-2serdk: remaster-openconnect-config-schema

## Description
Remaster the openconnect-tun config schema around an explicit default selection and a nested server -> profiles layout. Target model: default.server_url + default.profile at the root, then servers.<url>.profiles.<profile>.mode and profile-scoped split_include policy. Remove duplicated root policy, stop smearing one VPN policy across global, server, and profile layers, and keep a clear migration path for existing config.json users.

## Scope
(define task scope)

## Acceptance Criteria
(define acceptance criteria)
