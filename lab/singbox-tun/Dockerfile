# Lab image for the sing-box TUN A/B (see README.md). Build context: this directory, after the
# sing-box release tarball is in .runtime/dl. The lab binaries are built inside the image, so no
# host Go build and no stale host binary can enter it.
FROM golang:1.25-alpine AS build
WORKDIR /src
# The lab code imports only the standard library and its own packages under multi-tun/lab/...
RUN printf 'module multi-tun\n\ngo 1.25\n' > go.mod
COPY pattern ./lab/singbox-tun/pattern
COPY cmd ./lab/singbox-tun/cmd
RUN CGO_ENABLED=0 go build -o /out/labserver ./lab/singbox-tun/cmd/labserver \
 && CGO_ENABLED=0 go build -o /out/labclient ./lab/singbox-tun/cmd/labclient

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
COPY --from=build /out/labserver /out/labclient /usr/local/bin/
COPY singbox-system.json singbox-gvisor.json singbox-mixed.json /etc/lab/
