#!/usr/bin/env python3
import argparse
import socket
import threading
import time

def parse_requests(buffer: bytes):
    requests = []
    while True:
        hdr_end = buffer.find(b"\r\n\r\n")
        if hdr_end < 0:
            break
        header_block = buffer[:hdr_end]
        rest = buffer[hdr_end + 4:]
        content_length = 0
        for line in header_block.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    content_length = 0
                break
        if len(rest) < content_length:
            break
        body = rest[:content_length]
        req = buffer[:hdr_end + 4 + content_length]
        requests.append(req)
        buffer = rest[content_length:]
    return requests, buffer


def handle_client(conn: socket.socket, addr, args):
    conn.settimeout(1.0)
    buffer = b""
    peer = f"{addr[0]}:{addr[1]}"
    if args.verbose:
        print(f"[+] connected {peer}")
    try:
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                break
            except OSError:
                break
            if not data:
                break
            buffer += data
            reqs, buffer = parse_requests(buffer)
            for req in reqs:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                if args.verbose:
                    print(f"[{ts}] {peer} {len(req)} bytes")
                if args.save:
                    with open(args.save, "ab") as f:
                        f.write(req)
                        f.write(b"\n\n")
                if not args.no_response:
                    try:
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
                    except Exception:
                        pass
    finally:
        if args.verbose:
            print(f"[-] disconnected {peer}")
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Simple TCP HTTP server for bot tests")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--save", help="append raw requests to file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-response", action="store_true")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(128)
    print(f"listening on {args.host}:{args.port}")

    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, args), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

if __name__ == "__main__":
    main()
