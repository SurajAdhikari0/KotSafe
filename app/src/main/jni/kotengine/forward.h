#ifndef NETCAP_FORWARD_H
#define NETCAP_FORWARD_H

#include <stdint.h>
#include "conn_table.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * forward_engine: makes the VPN actually pass traffic, not just observe it.
 *
 * UDP is fully implemented here: each outbound UDP datagram from the TUN
 * gets a real backing socket (one per flow, protected from routing back
 * into the VPN via netcap_forward_set_protect_cb), forwarded to its real
 * destination, and replies are read back and re-encapsulated as IP
 * packets written back into the TUN fd.
 *
 * TCP is NOT implemented here. A correct TCP forwarder needs a real
 * TCP/IP state machine (SYN/ACK sequencing, retransmit timers, window
 * management) - reimplementing that from scratch is a multi-thousand-
 * line undertaking and a partial implementation would silently corrupt
 * or hang connections, which is worse than an honest gap. This header
 * exposes netcap_forward_set_tcp_backend() as the integration point:
 * plug in Google's gVisor netstack or tun2socks (both Apache-2.0, both
 * named in the original replacement guide) here rather than treating
 * this as solved.
 */

typedef int (*netcap_protect_fd_cb)(int fd, void *user_data);

typedef struct netcap_forward_engine netcap_forward_engine_t;

netcap_forward_engine_t *netcap_forward_create(int tun_fd);
void netcap_forward_destroy(netcap_forward_engine_t *fwd);

/* Must be called with a callback that wraps Android's VpnService.protect()
 * (via a JNI upcall) - without this, forwarded sockets would themselves
 * get routed back into the TUN and loop forever. */
void netcap_forward_set_protect_cb(netcap_forward_engine_t *fwd,
                                    netcap_protect_fd_cb cb, void *user_data);

/* Links the parent capture_engine to record received reply packets and throughput */
void netcap_forward_set_engine(netcap_forward_engine_t *fwd, void *engine);

/* Configures SOCKS5 proxy redirection for outbound TCP connections.
 * Set proxy_ip to NULL or proxy_port to 0 to disable proxy redirection. */
void netcap_forward_set_socks5_proxy(netcap_forward_engine_t *fwd,
                                     const char *proxy_ip, uint16_t proxy_port);

/* Handles one outbound IPv4/IPv6 UDP packet already parsed by
 * capture_engine.c. `ip_hdr_len` lets the caller pass the full packet so
 * we can rebuild the IP header for the reply without re-parsing. Returns
 * 0 if forwarded, -1 on error (caller should drop and log). */
int netcap_forward_handle_udp(netcap_forward_engine_t *fwd,
                               const netcap_flow_key_t *key,
                               const uint8_t *full_packet, uint32_t packet_len,
                               uint32_t ip_hdr_len, uint32_t udp_hdr_len,
                               const uint8_t *reply_src_ip);

/* Handles one outbound IPv4/IPv6 TCP packet already parsed by capture_engine.c.
 * Handles SYN connection establishment, payload relaying, and teardown.
 * Returns 0 if handled/forwarded, -1 on error. */
int netcap_forward_handle_tcp(netcap_forward_engine_t *fwd,
                               const netcap_flow_key_t *key,
                               const uint8_t *full_packet, uint32_t packet_len,
                               uint32_t ip_hdr_len, uint32_t tcp_hdr_len,
                               uint8_t tcp_flags, uint32_t seq, uint32_t ack);

/* Handles one outbound IPv4 ICMP echo request (ping) by relaying it through
 * an unprivileged ping socket. Replies are delivered by poll_replies.
 * Returns 0 if forwarded, -1 if unsupported/failed. */
int netcap_forward_handle_icmp(netcap_forward_engine_t *fwd,
                                const netcap_flow_key_t *key,
                                const uint8_t *full_packet, uint32_t packet_len,
                                uint32_t ip_hdr_len);

/* Polls all open UDP and TCP backing sockets for replies (non-blocking) and
 * writes any available reply packets back into the TUN fd. Call this
 * once per capture-loop iteration alongside the TUN read. */
void netcap_forward_poll_replies(netcap_forward_engine_t *fwd);

/* Closes UDP and TCP backing sockets idle longer than idle_secs. Call on the
 * same periodic tick as conn_table's idle sweep. */
void netcap_forward_sweep_idle(netcap_forward_engine_t *fwd, uint32_t idle_secs);

/* --- TCP integration point: unimplemented by design, see header note --- */
typedef struct {
    int (*handle_syn)(const netcap_flow_key_t *key, void *user_data);
    int (*handle_segment)(const netcap_flow_key_t *key, const uint8_t *payload,
                           uint32_t len, void *user_data);
    void *user_data;
} netcap_tcp_backend_t;

void netcap_forward_set_tcp_backend(netcap_forward_engine_t *fwd,
                                     const netcap_tcp_backend_t *backend);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_FORWARD_H */
