#!/usr/bin/env python3
import argparse
import socket
import sys
import time


def build_request(host_header: str, path: str) -> bytes:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: normal-client\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    return req.encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description="Send benign HTTP requests until disconnected")
    parser.add_argument("ip")
    parser.add_argument("port", type=int)
    parser.add_argument("--host-header", default="localhost")
    parser.add_argument("--path", default="/")
    parser.add_argument("--read-response", action="store_true")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    req = build_request(args.host_header, args.path)
    sent = 0

    try:
        with socket.create_connection((args.ip, args.port), timeout=args.timeout) as sock:
            sock.settimeout(args.timeout)
            while True:
                sock.sendall(req)
                sent += 1
                if args.verbose:
                    print(f"sent {sent}: benign request to {args.ip}:{args.port} path={args.path}")
                if args.read_response:
                    data = sock.recv(4096)
                    if not data:
                        raise ConnectionError("server closed connection")
                    if args.verbose:
                        print(data.decode("latin1", errors="replace"))
                if args.interval > 0:
                    time.sleep(args.interval)
    except OSError as exc:
        print(f"stopped after {sent} benign requests: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
