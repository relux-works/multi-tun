# Lab image for the sing-box TUN A/B (see README.md). Build context: this directory,
# after `go build` has written .runtime/bin/labserver and .runtime/bin/labclient and the
# sing-box release tarball is in .runtime/dl.
FROM alpine:3.22
RUN apk add --no-cache iproute2 ca-certificates
ARG SINGBOX_VERSION=1.13.3
ARG SINGBOX_SHA256=719df026d7acba848a03bcdf636c618216f2779288035191630abb50201f076d
# The release tarball is fetched on the host into .runtime/dl (see README.md) and verified here.
COPY .runtime/dl/sing-box-${SINGBOX_VERSION}-linux-arm64-musl.tar.gz /tmp/sb.tgz
RUN echo "${SINGBOX_SHA256}  /tmp/sb.tgz" | sha256sum -c - \
 && tar -xzf /tmp/sb.tgz -C /tmp \
 && mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-arm64-musl/sing-box" /usr/local/bin/sing-box \
 && rm -rf /tmp/sb.tgz "/tmp/sing-box-${SINGBOX_VERSION}-linux-arm64-musl"
COPY .runtime/bin/labserver .runtime/bin/labclient /usr/local/bin/
COPY singbox-system.json singbox-gvisor.json singbox-mixed.json /etc/lab/
