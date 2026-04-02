# BUG-260402-ye015v: openconnect-fetching-saml-config-hangs

## Description
openconnect-tun start stalls at auth_stage fetching_saml_config before SSO URL is surfaced; investigate whether the root cause is DNS/TLS reachability, aggregate-auth request handling, or missing diagnostics in the initial SAML config fetch path.

## Scope
(define bug scope / affected area)

## Acceptance Criteria
(define fix acceptance criteria)
