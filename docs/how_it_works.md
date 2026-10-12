# How KotSafe Operates

This document explains how traffic is managed by KotSafe in non-root and root modes.

KotSafe uses Android's `VpnService` to capture network traffic securely on the device without requiring root access. When the `VpnService` is active, IP packets from target applications are routed through a virtual network interface (TUN) directly to the **KotEngine** native C11 core (`libkotengine.so`).

## Architecture & Traffic Flow

```
+-------------+         Raw IP Packets         +----------------------------------+
| Client Apps | =============================> | KotSafe Android VPN Service      |
+-------------+                                +----------------------------------+
                                                                |
                                                 Zero-Copy TUN fd Handover
                                                                v
                                               +----------------------------------+
                                               | Native C11 KotEngine             |
                                               | - Lock-Free SPSC Ring Buffer     |
                                               | - Radix Trie CIDR / IP Filter    |
                                               | - JA4/JA4+ TLS Client Hello      |
                                               | - Shannon Entropy Analysis       |
                                               +----------------------------------+
                                                                |
                                                  Proxied L4 Sockets (TCP/UDP)
                                                                v
                                               +----------------------------------+
                                               | Upstream Physical Network        |
                                               | (Wi-Fi / Cellular / P2P Mesh)    |
                                               +----------------------------------+
```

## Key Mechanisms

1. **Clean-Room Lock-Free SPSC Ring Buffer (`packet_ring.c`)**:
   Instead of allocating byte arrays on the Java heap for every packet, KotEngine streams raw IP frames into a cache-line aligned single-producer single-consumer circular ring buffer. This completely eliminates GC pauses and drops packet latency to sub-microsecond levels.

2. **Sub-Microsecond Radix Trie Packet Filter (`trie_filter.c`)**:
   Enforces blocklists and firewall rules directly in C memory before proxying, dropping blocked packets instantly without Java overhead.

3. **JA4/JA4+ Client Hello Profiling (`ja4.c`)**:
   Parses TLS Client Hello messages directly on the wire to compute FoxIO JA4 fingerprints and Shannon entropy without needing TLS decryption.
