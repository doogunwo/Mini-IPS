# dd

Docker Compose based lab for running a small HTTP service, a normal client, a bot client, and an IPS container on an isolated bridge network.

## Components

- `server/`: simple Python HTTP server used as the protected target
- `normal/`: benign client that sends normal HTTP requests
- `bot/`: attack traffic generator and related C test payloads
- `ips/`: IPS implementation and support code
- `scripts/`: helper scripts for bringing the lab up, down, and tailing logs
- `runtime-logs/`: container log mount point generated at runtime and excluded from Git

## Requirements

- Docker
- Docker Compose
- GNU Make
- A C compiler such as `gcc`

## Quick Start

1. Copy the example environment file if you want to override defaults.
2. Build and start the containers.
3. Use the helper scripts or `docker compose` directly to inspect logs and shells.

```bash
cp .env.docker.example .env
docker compose up --build
```

To stop the stack:

```bash
docker compose down
```

## Development

Run unit tests from the repository root:

```bash
make units
```

Build the bot test binary:

```bash
make -C bot
```

## Repository Notes

- The repository excludes caches, logs, virtual environments, compiled objects, and local editor settings.
- `.env.docker.example` is safe to commit because it contains example values only.
- If you create a real `.env`, keep it local unless you intentionally want those values in the repository.
