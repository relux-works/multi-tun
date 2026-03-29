# TASK-260329-khq4d2: clear-stale-openconnect-session-on-auth-interrupt

## Description
Avoid leaving openconnect current-session runtime state behind when start is interrupted before a live PID exists. Cleanup must be safe for SIGINT during auth/bootstrap so later starts and overlay detection do not see pid=0 metadata.

## Scope
(define task scope)

## Acceptance Criteria
(define acceptance criteria)
