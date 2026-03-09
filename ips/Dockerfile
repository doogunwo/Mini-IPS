FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        make \
        libc6-dev \
        libpcap-dev \
        libpcre3-dev \
        libhyperscan-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN make clean && make main

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap0.8 \
        libpcre3 \
        libhyperscan5 \
        python3 \
        tzdata \
        iptables \
        iproute2 \
        procps && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /app/build
COPY --from=builder /app/build/main /app/main
COPY --from=builder /app/build/main /app/build/main
COPY --from=builder /app/rules /app/rules
COPY DB /app/DB
COPY image/run.sh /app/run.sh
COPY start.sh /app/start.sh
COPY start-log.sh /app/start-log.sh
RUN chmod +x /app/run.sh /app/start.sh /app/start-log.sh /app/main /app/build/main /app/DB/run_ingest.sh /app/DB/run_follow_ingest.sh /app/DB/run_web.sh
