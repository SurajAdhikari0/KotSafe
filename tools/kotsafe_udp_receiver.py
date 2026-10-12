#!/usr/bin/env python3
"""
KotSafe UDP Traffic Live Streaming Receiver.
Listens for streamed PCAP UDP packets from KotSafe and pipes them to stdout or Wireshark.

Example:
  python3 tools/kotsafe_udp_receiver.py -p 1234 | wireshark -k -i -
"""

import argparse
import socket
import sys

BUFSIZE = 65535
PCAP_HEADER_SIZE = 24
PCAP_HDR_MAGIC = bytes.fromhex("d4c3b2a1020004000000000000000000")
PCAP_HDR_RAW_SUFFIX = bytes.fromhex("ffff000065000000")    # LINKTYPE_RAW
PCAP_HDR_ETHER_SUFFIX = bytes.fromhex("ffff000001000000")  # LINKTYPE_ETHERNET

KOTSAFE_TRAILER_MAGIC = bytes.fromhex("01072021")
KOTSAFE_TRAILER_SIZE = 32

def main():
    parser = argparse.ArgumentParser(
        description="Receives streamed network packet dumps from KotSafe over UDP and pipes to stdout/Wireshark."
    )
    parser.add_argument("-p", "--port", type=int, default=1234, help="Local UDP listen port (default: 1234)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose status to stderr")
    parser.add_argument("-w", "--write", default="-", help="Output file path, or '-' for stdout")
    args = parser.parse_args()

    out_file = None
    if args.write != "-":
        out_file = open(args.write, "wb")

    def write_payload(data: bytes):
        if out_file:
            out_file.write(data)
        else:
            sys.stdout.buffer.write(data)
            sys.stdout.flush()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    if args.verbose:
        sys.stderr.write(f"[KotSafe] Listening on 0.0.0.0:{args.port}...\n")

    header_written = False
    try:
        while True:
            data, _ = sock.recvfrom(BUFSIZE)
            is_header = (len(data) == PCAP_HEADER_SIZE) and data.startswith(PCAP_HDR_MAGIC)

            if args.verbose:
                sys.stderr.write(f"[KotSafe] Received {len(data)} bytes\n")

            if not header_written and not is_header:
                trailer_offset = len(data) - KOTSAFE_TRAILER_SIZE
                has_trailer = (trailer_offset > 0) and (data[trailer_offset:trailer_offset + 4] == KOTSAFE_TRAILER_MAGIC)
                suffix = PCAP_HDR_ETHER_SUFFIX if has_trailer else PCAP_HDR_RAW_SUFFIX
                write_payload(PCAP_HDR_MAGIC + suffix)
                header_written = True

            elif is_header:
                if header_written:
                    continue
                header_written = True

            write_payload(data)

    except KeyboardInterrupt:
        if args.verbose:
            sys.stderr.write("\n[KotSafe] Receiver terminated by user.\n")
    finally:
        if out_file:
            out_file.close()

if __name__ == "__main__":
    main()
