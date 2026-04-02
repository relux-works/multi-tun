## Status
to-review

## Assigned To
codex

## Created
2026-04-02T13:32:05Z

## Last Update
2026-04-02T14:14:37Z

## Blocked By
- TASK-260402-1sq88o

## Blocks
- (none)

## Checklist
- [x] Rewrite the README vless config section after the schema remaster lands
- [x] Document each top-level field and clarify which fields are mode-specific

## Notes
Follow-up docs task for the vless-tun config reference once the remastered schema is settled in code.
Follow-up docs task for the vless-tun config reference once the remastered schema is settled in code. README should describe the new root tree, explain source.mode=proxy|direct, clarify launch as an optional override, and document the provider-neutral sing-box generated artifact path.
Follow-up docs task for the vless-tun config reference once the remastered schema is settled in code. README now describes the preferred source/default/network/launch/routing/dns/logging/artifacts tree, explains source.mode=proxy|direct, documents launch as an optional override rather than a required happy-path block, and switches the generated artifact language to provider-neutral sing-box config naming.
README cleaned up after the vless config remaster: provider-neutral generated artifact path now uses ~/.config/vless-tun/generated/sing-box.json, the vless config section documents source/default/network/launch/routing/dns/logging/artifacts, and only explicit compatibility notes remain for legacy flags.

## Precondition Resources
(none)

## Outcome Resources
(none)
