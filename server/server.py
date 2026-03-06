#!/usr/bin/env python3
import argparse
import socket
import struct
import threading
import time

blocked_ips = set()
blocked_ip_ports = set()
conn_map = {}
state_lock = threading.Lock()


def _tcp_info(sock: socket.socket):
    if not hasattr(socket, "TCP_INFO"):
        return None
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
    except OSError:
        return None
    if len(raw) < 104:
        return None

    vals = struct.unpack("=8B24I", raw[:104])
    return {
        "unacked": vals[12],
        "rtt_us": vals[23],
        "snd_cwnd": vals[26],
        "rcv_space": vals[30],
        "total_retrans": vals[31],
    }


def _log_tcp(peer: str, sock: socket.socket, app_tx_bytes: int, app_rx_bytes: int):
    info = _tcp_info(sock)
    if info is None:
        return
    print(
        f"[SRV][TCP] peer={peer} rel_seq={app_tx_bytes + 1} rel_ack={app_rx_bytes + 1} "
        f"unacked={info['unacked']} rcv_space={info['rcv_space']} "
        f"snd_cwnd={info['snd_cwnd']} rtt_us={info['rtt_us']} total_retrans={info['total_retrans']}"
    )

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
    app_rx_bytes = 0
    app_tx_bytes = 0
    peer = f"{addr[0]}:{addr[1]}"
    if args.verbose:
        print(f"[+] connected {peer}")
    with state_lock:
        conn_map[addr] = conn
    try:
        while True:
            with state_lock:
                if addr[0] in blocked_ips or addr in blocked_ip_ports:
                    break
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
                app_rx_bytes += len(req)
                if args.save:
                    with open(args.save, "ab") as f:
                        f.write(req)
                        f.write(b"\n\n")
                if not args.no_response:
                    try:
                        if args.latency_ms > 0:
                            time.sleep(args.latency_ms / 1000.0)
                        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK"
                        conn.sendall(resp)
                        app_tx_bytes += len(resp)
                    except Exception:
                        pass
                if args.verbose:
                    _log_tcp(peer, conn, app_tx_bytes, app_rx_bytes)
    finally:
        if args.verbose:
            print(f"[-] disconnected {peer}")
        with state_lock:
            conn_map.pop(addr, None)
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="Simple TCP HTTP server for bot tests")
    parser.add_argument("--host", default="10.0.0.2")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--save", help="append raw requests to file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-response", action="store_true")
    parser.add_argument("--latency-ms", type=int, default=0, help="delay each HTTP response by N ms")
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
