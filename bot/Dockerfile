FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        util-linux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN make clean && make

COPY image/run.sh /app/run.sh
RUN chmod +x /app/run.sh /app/start.sh /app/start-log.sh
