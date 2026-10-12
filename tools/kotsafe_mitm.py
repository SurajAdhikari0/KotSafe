#!/usr/bin/env python3
"""
KotSafe MITM Decryption Helper for mitmproxy.
Receives decrypted HTTP/WebSocket flows from mitmproxy and streams metadata to KotSafe.

Usage:
  mitmdump -q -p 8050 --mode socks5 -s kotsafe_mitm.py
"""

from enum import Enum
import errno
import socket
import sys
from mitmproxy import http
from mitmproxy.net.http.http1.assemble import assemble_request, assemble_response

class PayloadType(Enum):
    HTTP_REQUEST = "http_req"
    HTTP_REPLY = "http_rep"
    WEBSOCKET_CLIENT_MSG = "ws_climsg"
    WEBSOCKET_SERVER_MSG = "ws_srvmsg"

class KotSafeMitmProxy:
    def __init__(self, host="127.0.0.1", port=5750):
        self.host = host
        self.port = port
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"[KotSafe] Connected to KotSafe daemon on {self.host}:{self.port}")
        except socket.error as e:
            print(f"[KotSafe] Connection failed to {self.host}:{self.port}: {e}", file=sys.stderr)
            sys.exit(1)

    def send_payload(self, flow: http.HTTPFlow, payload_type: PayloadType, payload: bytes):
        if not flow.client_conn or not flow.client_conn.peername:
            return
        client_port = flow.client_conn.peername[1]
        header = f"{client_port}:{payload_type.value}:{len(payload)}\n"

        try:
            self.sock.sendall(header.encode('ascii'))
            self.sock.sendall(payload)
        except socket.error as e:
            if e.errno == errno.EPIPE:
                print("[KotSafe] Daemon closed connection", file=sys.stderr)
                sys.exit(0)
            else:
                print(f"[KotSafe] Error transmitting payload: {e}", file=sys.stderr)
                sys.exit(1)

    def request(self, flow: http.HTTPFlow):
        if flow.request:
            self.send_payload(flow, PayloadType.HTTP_REQUEST, assemble_request(flow.request))

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response:
            self.send_payload(flow, PayloadType.HTTP_REPLY, assemble_response(flow.response))

    def websocket_message(self, flow: http.HTTPFlow):
        if not flow.websocket or not flow.websocket.messages:
            return
        msg = flow.websocket.messages[-1]
        if not msg:
            return

        payload_type = PayloadType.WEBSOCKET_CLIENT_MSG if msg.from_client else PayloadType.WEBSOCKET_SERVER_MSG
        self.send_payload(flow, payload_type, msg.content)

addons = [
    KotSafeMitmProxy()
]
