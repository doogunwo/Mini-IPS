FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Seoul

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        make \
        pkg-config \
        libc6-dev \
        libpcap-dev \
        libpcre2-dev \
        libhyperscan-dev \
        python3 \
        tcpdump \
        tzdata \
        iptables \
        iproute2 \
        procps \
        util-linux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["sh", "-c", "trap : TERM INT; sleep infinity & wait"]
