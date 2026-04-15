# Docker Desktop on macOS — Internal Registry CA Setup

Use this note when `docker login`, `docker pull`, or `docker push` to an internal registry such as `registry.corp.example` fails with:

```text
x509: certificate signed by unknown authority
```

## What is happening

`Docker Desktop` runs the daemon inside its own Linux VM. On macOS it can trust corporate CAs from the host keychain, but that trust only becomes visible to Docker Desktop after the certificate is installed and Docker Desktop is restarted.

Official references:

- Docker Desktop for Mac FAQ: <https://docs.docker.com/desktop/troubleshoot-and-support/faqs/macfaqs/>
- Docker CA certificates guide: <https://docs.docker.com/engine/network/ca-certs/>
- Docker registry certificates guide: <https://docs.docker.com/engine/security/certificates/>

## Preferred Fix: Trust The CA In macOS

Install the registry CA chain into the macOS trust store, then restart Docker Desktop.

If you already have the CA certificate as `ca.crt`:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt
```

If you only want it in the current user's keychain:

```bash
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db ca.crt
```

If the internal registry uses both a corporate root and an intermediate CA, install both certificates.

After that:

```bash
osascript -e 'quit app "Docker Desktop"' || true
open -a "Docker Desktop"
```

## Alternative Fix: Per-Registry Docker Cert Directory

If you do not want to rely on the macOS keychain, add the CA bundle directly to Docker's client cert directory on the host and then restart Docker Desktop.

For a registry on the default TLS port:

```bash
mkdir -p ~/.docker/certs.d/registry.corp.example
cat company-root-ca.crt company-intermediate-ca.crt > ~/.docker/certs.d/registry.corp.example/ca.crt
```

For a registry on a custom port, include the port in the directory name:

```bash
mkdir -p ~/.docker/certs.d/registry.corp.example:5443
cat company-root-ca.crt company-intermediate-ca.crt > ~/.docker/certs.d/registry.corp.example:5443/ca.crt
```

Then restart Docker Desktop:

```bash
osascript -e 'quit app "Docker Desktop"' || true
open -a "Docker Desktop"
```

## Verify

```bash
docker login registry.corp.example
docker pull registry.corp.example/<repo>:<tag>
```

Expected result:

- no `x509: certificate signed by unknown authority`
- auth failures, missing tags, or permission errors are acceptable here because they prove TLS trust is fixed and Docker reached the registry

## Notes

- Do not mark the registry as `insecure`. Docker Desktop ignores certificates for insecure registries.
- If workloads inside containers also need to trust the same corporate CA, add the CA inside the image or running container too. Host trust only fixes the daemon's connection to the registry.
