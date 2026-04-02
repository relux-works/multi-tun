## Status
to-review

## Assigned To
codex

## Created
2026-04-02T12:06:25Z

## Last Update
2026-04-02T13:21:50Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Rewrite the README config example to match the remastered openconnect schema
- [x] Document cache_dir, default.server_url, default.profile, profile mode, and profile split_include semantics
- [x] State explicitly that vpn_domains are suffix masks and avoid redundant covered domain examples
- [x] Remove or replace stale explanations tied to the old top-level servers and profiles split

## Notes
Started incremental README config reference for openconnect-tun. Added a dedicated configuration subsection under the openconnect section and documented cache_dir as runtime/state storage with sessions/ and runtime/ examples.
Added default_profile to the README field reference. Documented that it is the default --profile selector, resolves a server from local AnyConnect XML when default_server is absent, and activates profiles.<name>.split_include overrides.
This README task should be completed only after the server-centric config redesign lands. It must explicitly document default_server semantics in addition to default_profile and the rest of the final openconnect config layout.
README follow-up aligned to the new openconnect config direction from 2026-04-02. This doc pass should happen only after TASK-260402-2serdk lands, and it should fully replace the interim notes that were written while we were still debating the schema shape. The final section should read from the user point of view of selecting a default server URL plus profile and configuring split_include per profile.
README openconnect config section refreshed on 2026-04-02 to match the remastered schema. The example now uses default.server_url plus default.profile at the root and nested servers.<url>.profiles.<profile>.mode plus split_include. The field reference documents cache_dir, default selection semantics, profile-level mode and split_include ownership, vpn_domains as suffix masks, and the need to avoid redundant covered domain entries such as inside.corp.example under corp.example. No code changes were needed in this slice; docs only.

## Precondition Resources
(none)

## Outcome Resources
(none)
