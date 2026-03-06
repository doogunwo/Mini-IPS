FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        iptables \
        iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py /app/server.py
EXPOSE 8080
