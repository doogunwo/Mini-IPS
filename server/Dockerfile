FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        iptables \
        iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py /app/server.py
COPY image/run.sh /app/run.sh
COPY start.sh /app/start.sh
COPY start-log.sh /app/start-log.sh
RUN chmod +x /app/run.sh /app/start.sh /app/start-log.sh
EXPOSE 8080
