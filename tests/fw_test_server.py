#!/usr/bin/env python3
"""
KotSafe Firewall Runtime Test Server
=====================================
Listens on multiple ports/protocols for the firewall bypass test suite.
Records every connection attempt with timestamp, source IP, port, protocol.
Provides a simple control API via stdin commands.
"""
import socket
import threading
import time
import sys
import json
import os
import select
import struct
import datetime

LOG_FILE = "/tmp/kotsafe_server.log"
HIT_FILE = "/tmp/kotsafe_hits.json"

hits = []
hits_lock = threading.Lock()
running = True

def ts():
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log(msg):
    line = f"[{ts()}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def record_hit(protocol, src_ip, src_port, dst_port, data=b""):
    hit = {
        "ts": ts(),
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "data_preview": data[:80].decode("utf-8", errors="replace") if data else ""
    }
    with hits_lock:
        hits.append(hit)
    # Write to file atomically for bash to poll
    with open(HIT_FILE, "w") as f:
        json.dump(hits, f, indent=2)
    log(f"HIT [{protocol}] {src_ip}:{src_port} → :{dst_port}  data={hit['data_preview']!r}")
    return hit

def tcp_listener(port, name="TCP"):
    try:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        srv.bind(("::", port))
        srv.listen(50)
        srv.settimeout(1)
        log(f"{name} listener ready on [::]:{port}")
        while running:
            try:
                conn, addr = srv.accept()
                data = b""
                try:
                    conn.settimeout(2)
                    data = conn.recv(512)
                    conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                except:
                    pass
                finally:
                    conn.close()
                record_hit(name, addr[0], addr[1], port, data)
            except socket.timeout:
                pass
            except Exception as e:
                if running:
                    log(f"{name}:{port} accept error: {e}")
        srv.close()
    except Exception as e:
        log(f"FATAL {name}:{port} — {e}")

def udp_listener(port):
    try:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        srv.bind(("::", port))
        srv.settimeout(1)
        log(f"UDP listener ready on [::]:{port}")
        while running:
            try:
                data, addr = srv.recvfrom(512)
                record_hit("UDP", addr[0], addr[1], port, data)
            except socket.timeout:
                pass
            except Exception as e:
                if running:
                    log(f"UDP:{port} recv error: {e}")
        srv.close()
    except Exception as e:
        log(f"FATAL UDP:{port} — {e}")

def dns_listener(port=5353):
    """Simple UDP listener on alt-DNS port to catch DNS bypass attempts."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.settimeout(1)
        log(f"DNS-probe listener ready on 0.0.0.0:{port}")
        while running:
            try:
                data, addr = srv.recvfrom(512)
                record_hit("DNS-UDP", addr[0], addr[1], port, data)
            except socket.timeout:
                pass
            except Exception as e:
                if running:
                    log(f"DNS-probe:{port} error: {e}")
        srv.close()
    except Exception as e:
        log(f"FATAL DNS-probe:{port} — {e}")

def hit_count_since(checkpoint_ts):
    """Count hits after a given timestamp string."""
    with hits_lock:
        return sum(1 for h in hits if h["ts"] > checkpoint_ts)

def clear_hits():
    with hits_lock:
        hits.clear()
    with open(HIT_FILE, "w") as f:
        json.dump([], f)
    log("Hit counter CLEARED")

def print_summary():
    with hits_lock:
        log(f"=== HIT SUMMARY: {len(hits)} total hits ===")
        for h in hits[-20:]:
            log(f"  {h['ts']} [{h['protocol']}] {h['src_ip']}:{h['src_port']} → :{h['dst_port']}")

if __name__ == "__main__":
    # Clear logs
    open(LOG_FILE, "w").close()
    open(HIT_FILE, "w").write("[]")

    # Start listeners
    ports_tcp = [8888, 8889, 9000, 9001]
    ports_udp = [8888, 9000]

    threads = []
    for p in ports_tcp:
        t = threading.Thread(target=tcp_listener, args=(p,), daemon=True)
        t.start(); threads.append(t)
        time.sleep(0.05)

    for p in ports_udp:
        t = threading.Thread(target=udp_listener, args=(p,), daemon=True)
        t.start(); threads.append(t)
        time.sleep(0.05)

    # t = threading.Thread(target=dns_listener, args=(5353,), daemon=True)
    # t.start(); threads.append(t)

    log(f"KotSafe Test Server started. TCP:{ports_tcp} UDP:{ports_udp}")
    log(f"Hit file: {HIT_FILE}")

    # Daemon loop — run until SIGTERM/SIGINT
    import signal
    def _shutdown(sig, frame):
        global running
        running = False

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    running = False
    log("Server shutting down")
    print_summary()
