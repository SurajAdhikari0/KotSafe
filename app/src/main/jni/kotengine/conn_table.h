#ifndef NETCAP_CONN_TABLE_H
#define NETCAP_CONN_TABLE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * conn_table: fixed-capacity open-addressing hash map keyed by the 5-tuple
 * (proto, src_ip, src_port, dst_ip, dst_port), with an intrusive doubly
 * linked LRU list threaded through the same slots.
 *
 * Design goals vs. a naive linear scan:
 *   - O(1) average lookup/insert/update instead of O(n) per-packet scan.
 *   - Bounded memory: capacity is fixed at creation; when full, the least
 *     recently used connection is evicted (with a callback so the engine
 *     can flush final stats before the slot is reused).
 *   - IPv4 and IPv6 both supported via a 16-byte address field (v4 stored
 *     as a mapped ::ffff:a.b.c.d style 16 bytes for a single code path).
 */

typedef enum {
    NETCAP_PROTO_TCP = 6,
    NETCAP_PROTO_UDP = 17,
    NETCAP_PROTO_OTHER = 0
} netcap_proto_t;

typedef enum {
    NETCAP_TCP_NEW = 0,
    NETCAP_TCP_SYN_SENT,
    NETCAP_TCP_ESTABLISHED,
    NETCAP_TCP_FIN_WAIT,
    NETCAP_TCP_CLOSED,
    NETCAP_TCP_RESET
} netcap_tcp_state_t;

typedef struct {
    uint8_t  proto;          /* netcap_proto_t */
    uint8_t  src_ip[16];     /* IPv4 stored in first 4 bytes when family==4 */
    uint8_t  dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  family;         /* 4 or 6 */
} netcap_flow_key_t;

typedef struct netcap_conn {
    netcap_flow_key_t key;

    uint64_t bytes_sent;
    uint64_t bytes_rcvd;
    uint32_t pkts_sent;
    uint32_t pkts_rcvd;

    time_t   first_seen;
    time_t   last_seen;

    netcap_tcp_state_t tcp_state; /* meaningful only when proto == TCP */
    uint8_t  seen_syn, seen_synack, seen_fin, seen_rst;

    uint64_t conn_id;        /* monotonic, never reused in a session: the identity Java should key on */
    uint8_t  closed;         /* 1 = tombstone: final stats already reported, kept briefly */
    time_t   closed_at;

    int32_t  uid;            /* resolved Android app UID, -1 if unknown */
    uint8_t  blacklisted;    /* set by the firewall/blacklist module */

    char     domain_name[128]; /* extracted via L7 inspector (SNI, DNS, HTTP Host) */
    char     l7_proto[16];     /* e.g. "TLS", "DNS", "HTTP", "QUIC" */
    char     ja4[37];          /* e.g. "t13d1516h2_8daaf6152771_0271701e699e" */
    float    entropy;          /* Shannon entropy (0.0 to 8.0) */
    uint8_t  is_suspicious_entropy; /* 1 if anomalous high entropy */
    char     country_code[3];  /* e.g. "US", "DE", "IN" */
    void     *payload_buf;     /* pointer to netcap_payload_buf_t if enabled */
    double   tx_bps;           /* live upload rate (bytes/s) */
    double   rx_bps;           /* live download rate (bytes/s) */
    void     *flow_meter;      /* pointer to netcap_flow_meter_t */

    /* intrusive slot bookkeeping - not for external use */
    uint32_t _occupied;
    uint32_t _lru_prev, _lru_next;
    uint32_t _hash_next;     /* separate chaining within the bucket array */
} netcap_conn_t;

typedef struct netcap_conn_table netcap_conn_table_t;

/* Called when a connection is evicted (LRU pressure) or explicitly closed,
 * so the caller can flush stats/logs before the record disappears. */
typedef void (*netcap_conn_evict_cb)(const netcap_conn_t *conn, void *user_data);

/* Creates a table with room for `capacity` simultaneous connections.
 * Returns NULL on allocation failure. */
netcap_conn_table_t *netcap_conn_table_create(uint32_t capacity,
                                               netcap_conn_evict_cb on_evict,
                                               void *user_data);

void netcap_conn_table_destroy(netcap_conn_table_t *t);

/* Looks up or creates the connection for `key`, updates last_seen, and
 * moves it to the MRU end of the LRU list. On creation under full
 * capacity, evicts the LRU entry first (invoking on_evict). Returns
 * a pointer valid until the next mutating call on this table (no
 * external free needed - storage is table-owned). */
netcap_conn_t *netcap_conn_table_touch(netcap_conn_table_t *t,
                                        const netcap_flow_key_t *key,
                                        time_t now);

/* Read-only lookup. NEVER creates an entry and does not touch LRU/last_seen,
 * so UI/JNI accessors cannot resurrect or keep alive a flow. May return a
 * tombstone (closed == 1). Pointer valid until the next mutating call. */
netcap_conn_t *netcap_conn_table_find(netcap_conn_table_t *t, const netcap_flow_key_t *key);

/* The only creation path for packet-driven flows.
 *  - live entry: returned (LRU touched), *created = 0.
 *  - tombstone + is_new_flow: replaced by a fresh entry with a NEW conn_id, *created = 1.
 *  - tombstone + !is_new_flow: returned unchanged (caller must not account into it).
 *  - no entry + !is_new_flow (mid-stream TCP): returns NULL, nothing created.
 * is_new_flow: TCP SYN without ACK; always 1 for UDP/ICMP/other. */
netcap_conn_t *netcap_conn_table_open(netcap_conn_table_t *t, const netcap_flow_key_t *key,
                                      int is_new_flow, time_t now, int *created);

/* Marks the flow closed exactly once: runs on_evict (final stats) now, keeps a
 * tombstone until netcap_conn_table_sweep_idle removes it. Idempotent. */
void netcap_conn_table_close(netcap_conn_table_t *t, netcap_conn_t *c, time_t now);

/* Explicit removal (e.g. clean TCP close / RST), invokes on_evict first. */
void netcap_conn_table_remove(netcap_conn_table_t *t, const netcap_flow_key_t *key);

/* Sweeps all connections idle longer than `idle_secs` and evicts them.
 * Call periodically (e.g. once per second) from the capture loop. */
void netcap_conn_table_sweep_idle(netcap_conn_table_t *t, time_t now, uint32_t idle_secs);

#define NETCAP_TOMBSTONE_SECS 2

uint32_t netcap_conn_table_count(const netcap_conn_table_t *t);

/* Iterates all live connections; callback returns 0 to continue, non-zero
 * to stop early. Safe to call from a "snapshot for UI" context - does not
 * mutate LRU order. */
typedef int (*netcap_conn_iter_cb)(const netcap_conn_t *conn, void *user_data);
void netcap_conn_table_foreach(const netcap_conn_table_t *t,
                                netcap_conn_iter_cb cb, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_CONN_TABLE_H */
