<div align="center">

# Mini-IPS

**A compact HTTP intrusion prevention system implemented in C**

![C](https://img.shields.io/badge/C-C11-A8B9CC?style=flat-square&logo=c&logoColor=black)
![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![PCRE2](https://img.shields.io/badge/Matching-PCRE2-315A9B?style=flat-square)
![Hyperscan](https://img.shields.io/badge/Matching-Hyperscan-7A3E9D?style=flat-square)
![Docker](https://img.shields.io/badge/Lab-Docker%20Compose-2496ED?style=flat-square&logo=docker&logoColor=white)

</div>

## Overview

Mini-IPS is an experimental HTTP intrusion prevention system that inspects application traffic, normalizes request data, evaluates signature rules, and blocks matching traffic. The repository includes both a transparent inline proxy path and a packet-sniffing path, together with a containerized client–router–server lab for controlled testing.

The implementation focuses on the complete inspection pipeline rather than only regular-expression matching:

- transparent traffic interception with Linux TPROXY;
- HTTP request parsing and stream handling;
- decoding and normalization before inspection;
- signature matching with PCRE2 or Hyperscan;
- request/response queues for worker processing;
- blocking responses and connection termination;
- structured event logging and monitoring; and
- unit, boundary, scenario, and Valgrind-oriented tests.

## Architecture

```text
Client network                    Server network
┌────────┐      ┌────────┐      ┌──────────────┐      ┌────────┐
│ Client │ ───► │ Router │ ───► │   Mini-IPS   │ ───► │ Server │
└────────┘      └────────┘      │              │      └────────┘
                                │ TPROXY relay │
                                │ HTTP parser  │
                                │ Normalize    │
                                │ Rule engine  │
                                │ Block / pass │
                                └──────────────┘
                                        │
                                        ▼
                              structured logs / SQLite
                                        │
                                        ▼
                                 monitoring pages
```

Docker Compose defines separate client and server bridge networks. The router forwards traffic between them, while the IPS container is attached and configured by the network setup scripts for inline inspection experiments.

## Inspection pipeline

### 1. Traffic interception

The inline implementation accepts transparently redirected connections through TPROXY, recovers the original destination, connects to the upstream server, and relays traffic in both directions using an epoll-based loop.

The repository also includes a sniffing implementation built around libpcap. It captures packets with a configurable BPF filter, distributes work through packet queues, reassembles HTTP streams, and runs detection without acting as the TCP relay.

### 2. HTTP parsing

Incoming data is parsed into HTTP request components before detection. The parser and stream layer handle request boundaries and provide the URI, path, query, headers, and body to the inspection stages.

### 3. Decoding and normalization

The normalization pipeline prepares evasive or differently encoded input for consistent matching. Implemented transformations include:

- URI and component decoding;
- path dot-segment removal;
- slash normalization;
- whitespace and line-ending normalization;
- lowercase normalization where required; and
- body normalization for supported text data.

### 4. Signature matching

Rules are loaded from JSON Lines files. Each signature contains a name, regular-expression pattern, score, and inspection context. The bundled rule groups cover:

- SQL injection;
- cross-site scripting;
- remote command execution; and
- directory traversal.

PCRE2 is the default matching backend. A separate build target uses Hyperscan for multi-pattern matching experiments. The `rules/tools/` scripts extract compatible expressions from OWASP Core Rule Set files into the repository's JSONL format.

### 5. Blocking and logging

When a request matches the configured policy, the inline path can generate a blocking response and terminate the flow. Detection, relay, queue, and timing data are written as structured key-value logs.

Python utilities under `ips/DB/` ingest those logs into SQLite and expose two lightweight views:

- an event browser for stored detection and blocking records; and
- a live monitor that follows periodic runtime statistics.

## Detection rule format

Rules use one JSON object per line:

```json
{
  "name": "XSS",
  "pat": "(?i)<script\\b[^>]*>",
  "score": 5,
  "ctx": "URI"
}
```

The loader separates signatures by attack family and compiles them for the selected matching engine.

## Implementation layout

```text
Mini-IPS/
├── ips/
│   ├── src/inline/       # TPROXY relay and inline inspection pipeline
│   ├── src/sniffing/     # libpcap capture and passive inspection pipeline
│   ├── src/common/       # Shared blocking-page helpers
│   ├── rules/            # JSONL signatures and CRS extraction tools
│   ├── tests/            # Unit, boundary, scenario, and Valgrind tests
│   ├── DB/               # Log ingestion, SQLite browser, and live monitor
│   └── Makefile          # Build, test, benchmark, and format targets
├── client/               # Normal and generated HTTP traffic clients
├── router/               # Containerized forwarding node
├── server/               # Protected HTTP test server
├── issues/               # Design and troubleshooting notes
├── docker-compose.yml    # Isolated client/router/IPS/server lab
└── start.sh              # Lab build and startup orchestration
```

## Build and verification targets

The `ips/Makefile` provides separate targets for the major implementations and validation paths.

| Target | Purpose |
| --- | --- |
| `main` / `inline-ips` | Build the PCRE2 inline IPS |
| `inline-ips-hs` | Build the Hyperscan inline IPS |
| `sniffing` | Build the libpcap-based sniffing IPS |
| `units` | Build and execute the test suite |
| `benchmark` | Build benchmark binaries |
| `run-benchmarks` | Execute the benchmark set and save logs |
| `valgrind-units` | Run unit binaries under Valgrind |
| `format-check` | Check C source formatting with clang-format |

## Test coverage

The test tree exercises individual modules and combined request-processing paths. It includes cases for:

- decoding and normalization boundaries;
- HTTP parser behavior;
- request and response ring buffers;
- rule loading and matching;
- blocking response construction;
- PCRE2 and Hyperscan engine integration;
- TPROXY helpers;
- large inputs and end-to-end pipeline scenarios; and
- detection-path memory checks under Valgrind.

## Project scope

Mini-IPS is a learning and evaluation project for exploring HTTP inspection internals, Linux transparent proxying, signature engines, and observable packet-processing pipelines. It is not presented as a production security appliance and should be evaluated in an isolated environment.
