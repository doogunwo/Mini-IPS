FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY normal_client.py /app/normal_client.py
COPY image/run.sh /app/run.sh
RUN chmod +x /app/run.sh
