FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nginx \
        util-linux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY index.html /app/index.html
COPY nginx.conf /etc/nginx/nginx.conf
COPY image/run.sh /app/run.sh
COPY start.sh /app/start.sh
COPY start-log.sh /app/start-log.sh
RUN chmod +x /app/run.sh /app/start.sh /app/start-log.sh
EXPOSE 80
