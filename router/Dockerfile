FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        procps && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh
