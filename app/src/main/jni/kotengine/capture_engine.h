#ifndef NETCAP_CAPTURE_ENGINE_H
#define NETCAP_CAPTURE_ENGINE_H

#include <stdint.h>
#include "conn_table.h"
#include "blacklist.h"
#include "ring_log.h"
#include "pcapng_writer.h"
#include "forward.h"
#include "payload_buffer.h"
#include "geoip.h"
#include "pcap_stream_server.h"
#include "dns_policy.h"
#include "proxy_relay.h"
#include "pcapng_secrets.h"
#include "quic_inspect.h"
#include "flow_meter.h"
#include "threat_detector.h"
#include "packet_ring.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * capture_engine: owns the TUN read loop and wires together conn_table,
 * blacklist, ring_log and (optionally) a pcapng_writer. Runs on its own
 * pthread so the JNI/UI thread is never blocked on packet I/O.
 *
 * Direction and firewall decisions are made per-packet:
 *   - Outbound packets (from the device, i.e. read from the TUN fd) are
 *     matched against the blacklist BEFORE being written back to the
 *     TUN's "uplink" path; blocked packets are dropped and never leave
 *     the device.
 *   - The UID of the owning app is resolved lazily (only on first sight
 *     of a connection) via /proc/net/{tcp,udp}[6], then cached in the
 *     connection record - avoids a /proc scan per packet.
 */

typedef struct {
    uint32_t max_connections;     /* conn_table capacity */
    uint32_t idle_timeout_secs;   /* sweep connections idle longer than this */
    uint32_t log_ring_capacity;   /* must be power of two */
    uint32_t snaplen;             /* 0 = unlimited, else bytes/packet for pcap dump */
    uint8_t  enable_uid_resolution;
    uint8_t  payload_mode;        /* 0 = NONE, 1 = MINIMAL (512B), 2 = FULL (32KB) */
} netcap_engine_config_t;

typedef struct netcap_engine netcap_engine_t;

/* Called (from the engine's internal thread, batched) whenever one or
 * more connections have changed since the last call, so the JNI layer
 * can forward a single upcall to Java instead of one per packet. */
typedef void (*netcap_conn_update_cb)(const netcap_conn_t *const *conns,
                                       uint32_t count, void *user_data);

netcap_engine_t *netcap_engine_create(const netcap_engine_config_t *cfg);
void netcap_engine_destroy(netcap_engine_t *engine);

/* Starts the capture loop reading from `tun_fd` (already established by
 * Android's VpnService.Builder.establish()). Non-blocking: spawns the
 * worker thread and returns immediately. Returns 0 on success. */
int netcap_engine_start(netcap_engine_t *engine, int tun_fd,
                         netcap_conn_update_cb on_update, void *user_data);

/* Signals the worker thread to stop and joins it. Safe to call from any
 * thread. Idempotent. */
void netcap_engine_stop(netcap_engine_t *engine);

/* Begins writing all subsequent packets to a PCAPng file at `path`.
 * Pass NULL to stop dumping. Returns 0 on success. */
int netcap_engine_set_pcap_dump(netcap_engine_t *engine, const char *path);

/* Attaches a forwarding engine (see forward.h) so outbound UDP packets
 * are actually relayed to their destination and replies written back
 * into the TUN, instead of only being inspected. Optional: if never
 * called, the engine behaves as inspection-only (nothing reaches the
 * real network - the previous, pre-forwarding behavior). TCP packets
 * are always passed to conn_table for tracking but are never forwarded
 * here - see forward.h's netcap_tcp_backend_t for that integration
 * point. */
void netcap_engine_attach_forward(netcap_engine_t *engine, netcap_forward_engine_t *fwd);

netcap_blacklist_t *netcap_engine_get_blacklist(netcap_engine_t *engine);
netcap_ring_log_t *netcap_engine_get_log(netcap_engine_t *engine);
const netcap_conn_table_t *netcap_engine_get_conn_table(netcap_engine_t *engine);

typedef struct {
    uint64_t pkts_sent;
    uint64_t bytes_sent;
    uint64_t pkts_rcvd;
    uint64_t bytes_rcvd;
    uint64_t blocked_pkts;
    uint64_t parse_errors;
    uint32_t active_connections;
    uint32_t total_connections;
    uint32_t dns_queries;
} netcap_engine_stats_t;

void netcap_engine_get_stats(const netcap_engine_t *engine, netcap_engine_stats_t *out);

/* Records reply packets and bytes arriving from upstream sockets */
void netcap_engine_record_reply(netcap_engine_t *engine, const netcap_flow_key_t *key, uint32_t bytes);

/* Real-time synchronous UID resolution callback */
typedef int32_t (*netcap_uid_resolver_cb)(uint8_t proto, const char *src_ip, uint16_t src_port,
                                          const char *dst_ip, uint16_t dst_port, void *user_data);
void netcap_engine_set_uid_resolver(netcap_engine_t *engine, netcap_uid_resolver_cb cb, void *user_data);

/* Starts the live PCAPng HTTP streaming server on the given port (e.g. 8080) */
int netcap_engine_start_stream_server(netcap_engine_t *engine, uint16_t port);
void netcap_engine_stop_stream_server(netcap_engine_t *engine);

/* Fetches payload for an active connection by 5-tuple key. Returns bytes written. */
uint32_t netcap_engine_get_conn_payload(netcap_engine_t *engine, const netcap_flow_key_t *key,
                                        int dir, uint8_t *out_buf, uint32_t max_len);

/* DNS and Network Policy configuration */
void netcap_engine_set_private_dns_blocked(netcap_engine_t *engine, bool blocked);
int netcap_engine_set_custom_dns(netcap_engine_t *engine, const char *dns_ip);
void netcap_engine_set_lan_blocked_uids(netcap_engine_t *engine, const int32_t *uids, size_t count);

/* Port and Proxy Redirection configuration */
int netcap_engine_add_proxy_rule(netcap_engine_t *engine, uint16_t orig_port, const char *target_ip, uint16_t target_port);
int netcap_engine_remove_proxy_rule(netcap_engine_t *engine, uint16_t orig_port);
void netcap_engine_set_proxy_exempt_uid(netcap_engine_t *engine, int32_t uid);
int netcap_engine_set_socks5_proxy(netcap_engine_t *engine, const char *proxy_ip, uint16_t proxy_port);

/* TLS Decryption Key Log Block (PCAPng DSB) injection */
int netcap_engine_add_tls_secret(netcap_engine_t *engine, const char *keylog_line);

/* Threat Alert Notification Callback */
typedef void (*netcap_threat_alert_cb)(const netcap_threat_alert_t *alert, void *user_data);
void netcap_engine_set_threat_callback(netcap_engine_t *engine, netcap_threat_alert_cb cb, void *user_data);

/* Live Connection Speed Query (EWMA Tx/Rx bytes per second) */
void netcap_engine_get_conn_speed(netcap_engine_t *engine, const netcap_flow_key_t *key,
                                  double *out_tx_bps, double *out_rx_bps);

/* DNS Reverse IP Cache & Answer Learning */
bool netcap_engine_lookup_dns_cache(netcap_engine_t *engine, const uint8_t *ip, uint8_t family,
                                    char *out_domain, size_t max_len);

/* Active Firewall Controls (App UID & Malicious Domain) */
void netcap_engine_set_blocked_uids(netcap_engine_t *engine, const int32_t *uids, size_t count);
void netcap_engine_add_blocked_domain(netcap_engine_t *engine, const char *domain);
void netcap_engine_remove_blocked_domain(netcap_engine_t *engine, const char *domain);
void netcap_engine_clear_blocked_domains(netcap_engine_t *engine);

/* Records reply packets and feeds DNS answers into cache */
void netcap_engine_record_reply_data(netcap_engine_t *engine, const netcap_flow_key_t *key,
                                     const uint8_t *payload, uint32_t payload_len, uint32_t total_wire_bytes);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_CAPTURE_ENGINE_H */
