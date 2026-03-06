FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        make \
        libc6-dev \
        libpcap-dev \
        libpcre3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
WORKDIR /app/ips
RUN make

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap0.8 \
        libpcre3 \
        iptables \
        iproute2 \
        procps && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/ips/main /app/main
