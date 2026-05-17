FROM debian:bookworm-slim

ARG SING_BOX_VERSION=1.13.3

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        jq \
        procps \
        python3 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      arm64) sb_arch="arm64" ;; \
      amd64) sb_arch="amd64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${sb_arch}.tar.gz"; \
    curl -fsSL "$url" -o /tmp/sing-box.tar.gz; \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp; \
    install -m 0755 "/tmp/sing-box-${SING_BOX_VERSION}-linux-${sb_arch}/sing-box" /usr/local/bin/sing-box; \
    rm -rf /tmp/sing-box*

RUN useradd -u 1000 -m -s /usr/sbin/nologin gate \
    && useradd -u 1001 -m -s /usr/sbin/nologin client \
    && mkdir -p /work /out

COPY sni-gate.py /usr/local/bin/sni-gate.py
COPY run-policy.sh /usr/local/bin/run-policy.sh

RUN chmod 0755 /usr/local/bin/sni-gate.py /usr/local/bin/run-policy.sh

ENTRYPOINT ["/usr/local/bin/run-policy.sh"]
