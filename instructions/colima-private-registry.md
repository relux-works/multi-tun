# Colima — Internal Registry CA And DNS Under OpenConnect

Use this note when `docker` is backed by `Colima` and an internal registry such as `registry.corp.example` behaves differently from ordinary host-side `curl`.

This usually falls into one of two buckets:

- TLS trust problem: `x509: certificate signed by unknown authority`
- guest DNS problem: `no such host`, DNS timeout, or the guest resolves the public IP while the macOS host resolves an internal VPN IP

## Quick Triage

Check what the guest sees:

```bash
colima ssh -- getent hosts registry.corp.example
colima ssh -- sh -lc 'curl -Ik --max-time 8 https://registry.corp.example/v2/'
docker login registry.corp.example
```

Interpretation:

- if `getent hosts` returns internal VPN IPs and `curl` reaches `/v2/`, but `docker login` fails with `x509`, fix CA trust
- if the host resolves the registry but `colima ssh -- getent hosts ...` does not, fix guest DNS first

## Fix 1: Install The Corporate CA Into Colima And Docker

Export the corporate root and intermediate CA certificates from macOS Keychain, or obtain them from the security team:

```bash
mkdir -p /tmp/company-ca

security find-certificate -c "Company Root CA" -p \
  /Library/Keychains/System.keychain \
  /System/Library/Keychains/SystemRootCertificates.keychain \
  > /tmp/company-ca/company-root-ca.crt

security find-certificate -c "Company Issuing CA" -p \
  /Library/Keychains/System.keychain \
  /System/Library/Keychains/SystemRootCertificates.keychain \
  > /tmp/company-ca/company-issuing-ca.crt
```

Copy them into the Colima guest trust store:

```bash
colima ssh -- sudo mkdir -p /usr/local/share/ca-certificates/company

cat /tmp/company-ca/company-root-ca.crt | \
  colima ssh -- sudo tee /usr/local/share/ca-certificates/company/company-root-ca.crt >/dev/null

cat /tmp/company-ca/company-issuing-ca.crt | \
  colima ssh -- sudo tee /usr/local/share/ca-certificates/company/company-issuing-ca.crt >/dev/null

colima ssh -- sudo update-ca-certificates
```

Install the same chain for the Docker daemon's per-registry trust:

```bash
colima ssh -- sudo mkdir -p /etc/docker/certs.d/registry.corp.example

cat /tmp/company-ca/company-root-ca.crt /tmp/company-ca/company-issuing-ca.crt | \
  colima ssh -- sudo tee /etc/docker/certs.d/registry.corp.example/ca.crt >/dev/null

colima ssh -- sudo systemctl restart docker
```

Verify:

```bash
docker login registry.corp.example
docker pull registry.corp.example/<repo>:<tag>
```

Expected result:

- `x509: certificate signed by unknown authority` is gone
- if you now see `unauthorized`, `denied`, or `manifest unknown`, the CA problem is fixed

## Fix 2: Force Colima DNS To VPN Resolvers

This is only for the case where the macOS host resolves the internal registry correctly through OpenConnect scoped DNS, but the Colima guest does not.

Edit `~/.colima/default/colima.yaml`:

```yaml
network:
  dns:
    - 10.0.0.10
    - 10.0.0.11
```

Then restart Colima:

```bash
colima stop
colima start
```

Re-check:

```bash
colima ssh -- getent hosts registry.corp.example
docker login registry.corp.example
```

## Last Resort: Pin A Single Hostname

If only one hostname matters and you cannot rely on guest DNS, pin it explicitly in `~/.colima/default/colima.yaml`:

```yaml
network:
  dnsHosts:
    registry.corp.example: 10.1.2.3
```

Then restart Colima:

```bash
colima stop
colima start
```

Use this only as a last resort because internal registry IPs can change.

## Notes

- `Colima` has a separate guest OS and a separate Docker daemon. Host trust in macOS Keychain does not automatically fix guest trust.
- Guest DNS under `OpenConnect` can diverge from host macOS DNS because the host may use scoped resolvers while the guest uses its own resolver path.
- If you set `network.dns`, the guest will send all DNS through those resolvers. Use that only when the default host-resolver path is unreliable under your VPN setup.
