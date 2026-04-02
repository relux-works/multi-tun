# BUG-260402-3uroj7: clear-orphaned-openconnect-resolver-state-without-session

## Description
When openconnect-tun leaves root-owned /etc/resolver split-include artifacts behind but runtime/current-session.json is already gone, stop/status cannot recover and official AnyConnect/SSO can fail on the stale Corp DNS overrides.

## Scope
(define bug scope / affected area)

## Acceptance Criteria
(define fix acceptance criteria)
