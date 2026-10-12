#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "capture_engine.h"
#include "l7_inspect.h"
#include "dns_cache.h"
#include "dns_sinkhole.h"
#include "firewall.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>

#define MAX_PACKET 65536
#define UPDATE_BATCH_MAX 64
#define UID_CACHE_TTL_SECS 30

struct netcap_engine {
    netcap_engine_config_t cfg;

    netcap_conn_table_t *conns;
    netcap_blacklist_t *blacklist;
    netcap_ring_log_t log;

    pthread_t worker;
    pthread_mutex_t dump_lock;
    netcap_pcapng_writer_t *dump; /* protected by dump_lock */

    int tun_fd;
    volatile int running;

    netcap_conn_update_cb on_update;
    void *update_user_data;

    pthread_mutex_t stats_lock;
    netcap_engine_stats_t stats;

    netcap_forward_engine_t *fwd; /* NULL = inspection-only, no relaying */
    netcap_stream_server_t *stream_srv; /* NULL = no live PCAP streaming */

    netcap_dns_policy_t *dns_policy;
    netcap_dns_cache_t *dns_cache;
    netcap_firewall_t *firewall;
    netcap_proxy_relay_t *proxy_relay;
    netcap_secrets_store_t *secrets;

    netcap_threat_detector_t *threats;
    netcap_threat_alert_cb on_threat;
    void *threat_user_data;

    netcap_uid_resolver_cb uid_resolver;
    void *uid_user_data;

    char socks5_proxy_ip[64];
    uint16_t socks5_proxy_port;
    bool socks5_enabled;
};

/* ---- minimal packet header views (network byte order on the wire) ---- */

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint8_t src[4];
    uint8_t dst[4];
} __attribute__((packed)) ipv4_hdr_t;

typedef struct {
    uint32_t ver_class_flow;
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
} __attribute__((packed)) ipv6_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off_reserved;
    uint8_t  flags;
} __attribute__((packed)) tcp_hdr_min_t;

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) udp_hdr_t;

/* ---- uid resolution (lazy /proc scan, cached per-connection by caller) --- */

/* Looks up the owning UID for a local port by scanning /proc/net/{tcp,udp}.
 * This is O(open sockets on the device), so callers should only invoke it
 * once per new connection (the conn_table entry caches the result), not
 * per packet. */
static int32_t resolve_uid_for_port(uint16_t local_port, uint8_t proto, uint8_t family) {
    const char *path;
    if (proto == NETCAP_PROTO_TCP)
        path = (family == 4) ? "/proc/net/tcp" : "/proc/net/tcp6";
    else if (proto == NETCAP_PROTO_UDP)
        path = (family == 4) ? "/proc/net/udp" : "/proc/net/udp6";
    else
        return -1;

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    fgets(line, sizeof(line), fp); /* discard header */
    int32_t found_uid = -1;
    unsigned local_addr_port_hi, local_port_hex;
    char local_field[128];

    while (fgets(line, sizeof(line), fp)) {
        unsigned uid = 0;
        /* format: "  N: LOCALADDR:PORT REMOTEADDR:PORT ST ... UID ..." */
        if (sscanf(line, " %*d: %127s", local_field) != 1) continue;
        char *colon = strrchr(local_field, ':');
        if (!colon) continue;
        local_port_hex = (unsigned)strtoul(colon + 1, NULL, 16);
        if (local_port_hex != local_port) continue;

        /* uid is the 8th whitespace-separated field; parse generically */
        int field = 0;
        char *tok = strtok(line, " \t");
        while (tok) {
            field++;
            if (field == 8) { uid = (unsigned)strtoul(tok, NULL, 10); break; }
            tok = strtok(NULL, " \t");
        }
        found_uid = (int32_t)uid;
        break;
    }
    (void)local_addr_port_hi;
    fclose(fp);
    return found_uid;
}

/* ---- packet handling ---- */

typedef struct {
    netcap_flow_key_t key;
    const uint8_t *l4;
    uint32_t l4_len;
    uint32_t ip_hdr_len; /* needed to hand the raw packet to forward.c without re-parsing */
    uint32_t l4_hdr_len;
    uint8_t tcp_flags;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    int is_outbound; /* always 1 for a device-side TUN read; kept for future dual-direction support */
} parsed_pkt_t;

static void ip_to_string(const uint8_t *addr, uint8_t family, char *out, size_t out_sz) {
    if (family == 4) {
        snprintf(out, out_sz, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    } else {
        snprintf(out, out_sz,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                 addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    }
}

static int parse_ipv4(const uint8_t *pkt, uint32_t len, parsed_pkt_t *out) {
    if (len < sizeof(ipv4_hdr_t)) return -1;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)pkt;
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    if (ihl < sizeof(ipv4_hdr_t) || len < ihl) return -1;

    out->key.family = 4;
    memset(out->key.src_ip, 0, 16);
    memset(out->key.dst_ip, 0, 16);
    memcpy(out->key.src_ip, ip->src, 4);
    memcpy(out->key.dst_ip, ip->dst, 4);
    out->key.proto = ip->proto;
    out->l4 = pkt + ihl;
    out->l4_len = len - ihl;
    out->ip_hdr_len = ihl;
    return 0;
}

static int parse_ipv6(const uint8_t *pkt, uint32_t len, parsed_pkt_t *out) {
    if (len < sizeof(ipv6_hdr_t)) return -1;
    const ipv6_hdr_t *ip = (const ipv6_hdr_t *)pkt;
    out->key.family = 6;
    memcpy(out->key.src_ip, ip->src, 16);
    memcpy(out->key.dst_ip, ip->dst, 16);
    out->key.proto = ip->next_hdr; /* NB: extension headers not walked - acceptable for typical UDP/TCP traffic */
    out->l4 = pkt + sizeof(ipv6_hdr_t);
    out->l4_len = len - sizeof(ipv6_hdr_t);
    out->ip_hdr_len = sizeof(ipv6_hdr_t);
    return 0;
}

static int parse_l4_ports(parsed_pkt_t *p) {
    if (p->key.proto == NETCAP_PROTO_TCP) {
        if (p->l4_len < sizeof(tcp_hdr_min_t)) return -1;
        const tcp_hdr_min_t *tcp = (const tcp_hdr_min_t *)p->l4;
        p->key.src_port = ntohs(tcp->src_port);
        p->key.dst_port = ntohs(tcp->dst_port);
        p->tcp_flags = tcp->flags;
        p->tcp_seq = ntohl(tcp->seq);
        p->tcp_ack = ntohl(tcp->ack);
        p->l4_hdr_len = ((tcp->data_off_reserved >> 4) & 0x0F) * 4;
        if (p->l4_hdr_len < sizeof(tcp_hdr_min_t) || p->l4_len < p->l4_hdr_len) {
            p->l4_hdr_len = sizeof(tcp_hdr_min_t);
        }
        return 0;
    }
    if (p->key.proto == NETCAP_PROTO_UDP) {
        if (p->l4_len < sizeof(udp_hdr_t)) return -1;
        const udp_hdr_t *udp = (const udp_hdr_t *)p->l4;
        p->key.src_port = ntohs(udp->src_port);
        p->key.dst_port = ntohs(udp->dst_port);
        p->tcp_flags = 0;
        p->l4_hdr_len = sizeof(udp_hdr_t);
        return 0;
    }
    p->key.src_port = 0;
    p->key.dst_port = 0;
    p->tcp_flags = 0;
    p->l4_hdr_len = 0;
    return 0; /* still track non-TCP/UDP protocols (ICMP etc.) by IP pair */
}

static void update_tcp_state(netcap_conn_t *c, uint8_t flags) {
    if (flags & TCP_FLAG_RST) { c->seen_rst = 1; c->tcp_state = NETCAP_TCP_RESET; return; }
    if (flags & TCP_FLAG_SYN) {
        if (flags & TCP_FLAG_ACK) c->seen_synack = 1;
        else c->seen_syn = 1;
        if (c->tcp_state == NETCAP_TCP_NEW) c->tcp_state = NETCAP_TCP_SYN_SENT;
    }
    if (c->seen_syn && c->seen_synack && c->tcp_state != NETCAP_TCP_CLOSED)
        c->tcp_state = NETCAP_TCP_ESTABLISHED;
    if (flags & TCP_FLAG_FIN) {
        c->seen_fin = 1;
        c->tcp_state = NETCAP_TCP_FIN_WAIT;
    }
}

/* on_evict trampoline: logs a one-line summary when a connection is
 * dropped from the table (idle timeout or LRU pressure). */
static void engine_on_conn_evict(const netcap_conn_t *conn, void *user_data) {
    netcap_engine_t *e = (netcap_engine_t *)user_data;
    char msg[NETCAP_LOG_MSG_MAX];
    snprintf(msg, sizeof(msg), "conn closed proto=%u uid=%d sent=%llu rcvd=%llu",
             conn->key.proto, conn->uid,
             (unsigned long long)conn->bytes_sent, (unsigned long long)conn->bytes_rcvd);
    netcap_ring_log_push(&e->log, 1, msg);
}

netcap_engine_t *netcap_engine_create(const netcap_engine_config_t *cfg) {
    netcap_engine_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->cfg = *cfg;
    e->tun_fd = -1;

    e->conns = netcap_conn_table_create(cfg->max_connections, engine_on_conn_evict, e);
    e->blacklist = netcap_blacklist_create();
    e->dns_policy = netcap_dns_policy_create();
    e->dns_cache = netcap_dns_cache_create(2048);
    e->firewall = netcap_firewall_create();
    e->proxy_relay = netcap_proxy_relay_create();
    e->secrets = netcap_secrets_create(256);
    e->threats = netcap_threat_detector_create();

    if (!e->conns || !e->blacklist || !e->dns_policy || !e->dns_cache || !e->firewall ||
        !e->proxy_relay || !e->secrets || !e->threats ||
        netcap_ring_log_init(&e->log, cfg->log_ring_capacity) != 0) {
        netcap_conn_table_destroy(e->conns);
        netcap_blacklist_destroy(e->blacklist);
        netcap_dns_policy_destroy(e->dns_policy);
        netcap_dns_cache_destroy(e->dns_cache);
        netcap_firewall_destroy(e->firewall);
        netcap_proxy_relay_destroy(e->proxy_relay);
        netcap_secrets_destroy(e->secrets);
        netcap_threat_detector_destroy(e->threats);
        free(e);
        return NULL;
    }

    pthread_mutex_init(&e->dump_lock, NULL);
    pthread_mutex_init(&e->stats_lock, NULL);
    return e;
}

void netcap_engine_destroy(netcap_engine_t *e) {
    if (!e) return;
    netcap_engine_stop(e);
    if (e->stream_srv) netcap_stream_server_destroy(e->stream_srv);
    netcap_pcapng_close(e->dump);
    netcap_conn_table_destroy(e->conns);
    netcap_blacklist_destroy(e->blacklist);
    netcap_dns_policy_destroy(e->dns_policy);
    netcap_dns_cache_destroy(e->dns_cache);
    netcap_firewall_destroy(e->firewall);
    netcap_proxy_relay_destroy(e->proxy_relay);
    netcap_secrets_destroy(e->secrets);
    netcap_threat_detector_destroy(e->threats);
    netcap_ring_log_destroy(&e->log);
    pthread_mutex_destroy(&e->dump_lock);
    pthread_mutex_destroy(&e->stats_lock);
    free(e);
}
static inline uint16_t compute_ip_csum(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline uint32_t csum_accumulate(uint32_t sum, const uint8_t *data, uint32_t len) {
    while (len > 1) { sum += ((uint32_t)data[0] << 8) | data[1]; data += 2; len -= 2; }
    if (len) sum += (uint32_t)data[0] << 8;
    return sum;
}

static inline uint16_t csum_fold_val(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static void write_tcp_rst_packet(int tun_fd, const parsed_pkt_t *p) {
    if (tun_fd < 0 || p->key.proto != NETCAP_PROTO_TCP) return;
    if (p->key.family == 4) {
        uint8_t pkt[40] = {0};
        pkt[0] = 0x45;
        pkt[2] = 0; pkt[3] = 40;
        pkt[8] = 64;
        pkt[9] = IPPROTO_TCP;
        memcpy(pkt + 12, p->key.dst_ip, 4);
        memcpy(pkt + 16, p->key.src_ip, 4);
        uint16_t ipcsum = compute_ip_csum(pkt, 20);
        memcpy(pkt + 10, &ipcsum, 2);

        uint8_t *tcp = pkt + 20;
        uint16_t sp = htons(p->key.dst_port), dp = htons(p->key.src_port);
        memcpy(tcp, &sp, 2); memcpy(tcp + 2, &dp, 2);
        uint32_t ack = htonl(p->tcp_seq + 1);
        memcpy(tcp + 8, &ack, 4);
        tcp[12] = 0x50;
        tcp[13] = TCP_FLAG_RST | TCP_FLAG_ACK;
        uint8_t ph[8] = { 0, 0, 0, 20, 0, 0, 0, IPPROTO_TCP };
        uint32_t sum = csum_accumulate(0, pkt + 12, 8);
        sum = csum_accumulate(sum, ph, 8);
        sum = csum_accumulate(sum, tcp, 20);
        uint16_t tcpcsum = csum_fold_val(sum);
        memcpy(tcp + 16, &tcpcsum, 2);
        if (write(tun_fd, pkt, 40) < 0) { /* ignore */ }
    }
}

static void *worker_main(void *arg) {
    netcap_engine_t *e = (netcap_engine_t *)arg;
    uint8_t buf[MAX_PACKET];
    time_t last_sweep = time(NULL);

    const netcap_conn_t *batch[UPDATE_BATCH_MAX];
    uint32_t batch_n = 0;

    struct pollfd pfd;
    pfd.fd = e->tun_fd;
    pfd.events = POLLIN;

    while (e->running) {
        time_t now = time(NULL);

        /* 1. Poll TUN fd with short 5ms timeout so we don't stall server replies */
        int prc = poll(&pfd, 1, 5);
        if (prc > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = read(e->tun_fd, buf, sizeof(buf));
            if (n > 0) {
                uint8_t ip_ver = (buf[0] >> 4) & 0x0F;

                parsed_pkt_t p = {0};
                int ok = (ip_ver == 4) ? parse_ipv4(buf, (uint32_t)n, &p)
                       : (ip_ver == 6) ? parse_ipv6(buf, (uint32_t)n, &p)
                       : -1;
                if (ok == 0) ok = parse_l4_ports(&p);

                pthread_mutex_lock(&e->stats_lock);
                e->stats.pkts_sent++;
                e->stats.bytes_sent += (uint64_t)n;
                if (ok == 0 && (p.key.dst_port == 53 || p.key.dst_port == 5353 || p.key.src_port == 53 || p.key.src_port == 5353)) {
                    e->stats.dns_queries++;
                }
                if (ok != 0) e->stats.parse_errors++;
                pthread_mutex_unlock(&e->stats_lock);

                if (ok == 0) {
                    uint8_t orig_dst_ip[16];
                    memcpy(orig_dst_ip, p.key.dst_ip, 16);

                    /* Block Private DNS (DoT / Port 853) to force Android to fall back to port 53 */
                    if (p.key.dst_port == 853 && netcap_dns_policy_is_dot_blocked(e->dns_policy)) {
                        pthread_mutex_lock(&e->stats_lock);
                        e->stats.blocked_pkts++;
                        pthread_mutex_unlock(&e->stats_lock);
                    } else {
                        /* Custom DNS Redirection (port 53 UDP) */
                        if (p.key.dst_port == 53 && p.key.proto == NETCAP_PROTO_UDP) {
                            if (netcap_dns_policy_rewrite_dns_packet(e->dns_policy, buf, (uint32_t)n, p.ip_hdr_len, p.key.family)) {
                                if (p.key.family == 4) {
                                    memcpy(p.key.dst_ip, buf + 16, 4);
                                } else if (p.key.family == 6) {
                                    memcpy(p.key.dst_ip, buf + 24, 16);
                                }
                            }
                        }

                        /* Touch or lookup connection entry early to obtain cached UID */
                        netcap_conn_t *c = netcap_conn_table_touch(e->conns, &p.key, now);
                        if (c && c->pkts_sent == 0 && c->pkts_rcvd == 0) {
                            pthread_mutex_lock(&e->stats_lock);
                            e->stats.total_connections++;
                            pthread_mutex_unlock(&e->stats_lock);
                        }
                        int32_t uid = (c && c->uid >= 0) ? c->uid : -1;
                        if (uid < 0) {
                            if (e->uid_resolver) {
                                char src_str[48], dst_str[48];
                                ip_to_string(p.key.src_ip, p.key.family, src_str, sizeof(src_str));
                                ip_to_string(p.key.dst_ip, p.key.family, dst_str, sizeof(dst_str));
                                uid = e->uid_resolver(p.key.proto, src_str, p.key.src_port, dst_str, p.key.dst_port, e->uid_user_data);
                            }
                            if (uid < 0 && e->cfg.enable_uid_resolution) {
                                uid = resolve_uid_for_port(p.key.src_port, p.key.proto, p.key.family);
                            }
                            if (uid < 0) {
                                if (p.key.dst_port == 53 || p.key.dst_port == 5353 || p.key.src_port == 53 ||
                                    p.key.proto == 1 /* ICMP */ || p.key.proto == 58 /* ICMPv6 */) {
                                    uid = 1000; /* Android System UID fallback */
                                }
                            }
                            if (c && uid >= 0) c->uid = uid;
                        }

                        /* 1. App Firewall: Complete Internet Egress Block */
                        if (uid >= 0 && netcap_firewall_is_uid_blocked(e->firewall, uid)) {
                            pthread_mutex_lock(&e->stats_lock);
                            e->stats.blocked_pkts++;
                            pthread_mutex_unlock(&e->stats_lock);
                            if (c) c->blacklisted = 1;
                            if (p.key.proto == NETCAP_PROTO_TCP) write_tcp_rst_packet(e->tun_fd, &p);
                            continue;
                        }

                        /* 2. Per-App LAN Isolation */
                        if (uid >= 0 && netcap_dns_policy_is_lan_blocked(e->dns_policy, uid, p.key.dst_ip, p.key.family)) {
                            pthread_mutex_lock(&e->stats_lock);
                            e->stats.blocked_pkts++;
                            pthread_mutex_unlock(&e->stats_lock);
                            if (c) c->blacklisted = 1;
                            continue;
                        }

                        /* 3. DNS Active Interception & RFC 1035 Sinkholing */
                        if (p.key.proto == NETCAP_PROTO_UDP && (p.key.dst_port == 53 || p.key.dst_port == 5353)) {
                            const uint8_t *dns_payload = buf + p.ip_hdr_len + p.l4_hdr_len;
                            size_t dns_payload_len = (size_t)n - p.ip_hdr_len - p.l4_hdr_len;
                            char queried_domain[256] = {0};

                            if (netcap_is_dns_query(p.key.proto, p.key.dst_port, dns_payload, dns_payload_len) &&
                                netcap_dns_extract_qname(dns_payload, dns_payload_len, queried_domain, sizeof(queried_domain))) {

                                if (c && c->domain_name[0] == '\0') {
                                    strncpy(c->domain_name, queried_domain, sizeof(c->domain_name) - 1);
                                    c->domain_name[sizeof(c->domain_name) - 1] = '\0';
                                }

                                if (netcap_firewall_is_domain_blocked(e->firewall, queried_domain)) {
                                    uint8_t sinkhole_pkt[512];
                                    size_t sh_len = netcap_dns_synthesize_sinkhole_packet(buf, (size_t)n, p.ip_hdr_len, p.key.family,
                                                                                          sinkhole_pkt, sizeof(sinkhole_pkt));
                                    if (sh_len > 0 && e->tun_fd >= 0) {
                                        if (write(e->tun_fd, sinkhole_pkt, sh_len) < 0) { /* ignore */ }
                                    }

                                    pthread_mutex_lock(&e->stats_lock);
                                    e->stats.blocked_pkts++;
                                    pthread_mutex_unlock(&e->stats_lock);

                                    if (c) c->blacklisted = 1;

                                    if (e->threats && e->on_threat) {
                                        netcap_threat_alert_t alert;
                                        memset(&alert, 0, sizeof(alert));
                                        alert.type = 3; /* THREAT_TYPE_DNS_BLOCKED */
                                        alert.uid = uid;
                                        alert.timestamp_ms = (uint64_t)now * 1000;
                                        snprintf(alert.details, sizeof(alert.details), "Blocked Domain: %.90s (DNS Sinkholed)", queried_domain);
                                        e->on_threat(&alert, e->threat_user_data);
                                    }

                                    if (batch_n < UPDATE_BATCH_MAX && c) batch[batch_n++] = c;
                                    continue; /* SINKHOLED: DO NOT FORWARD */
                                }
                            }
                        }

                        /* 4. Reverse DNS Cache: Auto-populate domain for IP connections */
                        if (c && c->domain_name[0] == '\0') {
                            char cached_dom[256] = {0};
                            if (netcap_dns_cache_lookup(e->dns_cache, c->key.dst_ip, c->key.family, cached_dom, sizeof(cached_dom))) {
                                strncpy(c->domain_name, cached_dom, sizeof(c->domain_name) - 1);
                                c->domain_name[sizeof(c->domain_name) - 1] = '\0';
                            }
                        }

                        /* Enhanced Port & Proxy Redirection */
                        uint8_t redir_ip[16];
                        uint16_t redir_port = 0;
                        if (netcap_proxy_relay_rewrite_packet(e->proxy_relay, uid, buf, (uint32_t)n, p.ip_hdr_len,
                                                              p.key.proto, p.key.family, redir_ip, &redir_port)) {
                            memcpy(p.key.dst_ip, redir_ip, (p.key.family == 4) ? 4 : 16);
                            p.key.dst_port = redir_port;
                        }

                        /* Destination Blacklist check */
                        int blocked = netcap_blacklist_match(e->blacklist, p.key.dst_ip, p.key.family);
                        if (blocked) {
                            pthread_mutex_lock(&e->stats_lock);
                            e->stats.blocked_pkts++;
                            pthread_mutex_unlock(&e->stats_lock);
                            if (c) c->blacklisted = 1;
                            if (p.key.proto == NETCAP_PROTO_TCP) write_tcp_rst_packet(e->tun_fd, &p);
                            continue;
                        }

                        if (c) {
                            c->bytes_sent += (uint64_t)n;
                            c->pkts_sent++;
                            if (p.key.proto == NETCAP_PROTO_TCP) update_tcp_state(c, p.tcp_flags);
                            if (uid >= 0 && c->uid < 0) c->uid = uid;

                                    /* Real-time EWMA bandwidth & speed calculation */
                                    if (!c->flow_meter) {
                                        c->flow_meter = calloc(1, sizeof(netcap_flow_meter_t));
                                        if (c->flow_meter) netcap_flow_meter_init((netcap_flow_meter_t *)c->flow_meter, (uint64_t)now * 1000);
                                    }
                                    if (c->flow_meter) {
                                        netcap_flow_meter_record((netcap_flow_meter_t *)c->flow_meter, p.is_outbound, (uint32_t)n, (uint64_t)now * 1000);
                                        netcap_flow_meter_t *fm = (netcap_flow_meter_t *)c->flow_meter;
                                        c->tx_bps = fm->tx_bps;
                                        c->rx_bps = fm->rx_bps;
                                    }

                                    /* Port scan and suspicious port heuristics */
                                    if (e->threats && e->on_threat) {
                                        netcap_threat_alert_t alert;
                                        if (netcap_threat_inspect_flow(e->threats, c->uid, p.key.dst_port, (uint64_t)now * 1000, &alert)) {
                                            e->on_threat(&alert, e->threat_user_data);
                                        }
                                    }

                                    /* GeoIP country resolution */
                                    if (c->country_code[0] == '\0') {
                                        const char *cc = netcap_geoip_lookup(c->key.dst_ip, c->key.family);
                                        if (cc && cc[0]) {
                                            strncpy(c->country_code, cc, 2);
                                            c->country_code[2] = '\0';
                                        }
                                    }

                                    /* L7 domain and protocol inspection */
                                    if (p.l4_len > p.l4_hdr_len && c->domain_name[0] == '\0') {
                                        const uint8_t *payload = p.l4 + p.l4_hdr_len;
                                        size_t payload_len = p.l4_len - p.l4_hdr_len;
                                        netcap_l7_info_t l7_info;
                                        if (netcap_l7_inspect(p.key.proto, p.key.src_port, p.key.dst_port,
                                                              payload, payload_len, &l7_info)) {
                                            if (l7_info.has_domain) {
                                                strncpy(c->domain_name, l7_info.domain, sizeof(c->domain_name) - 1);
                                                c->domain_name[sizeof(c->domain_name) - 1] = '\0';
                                            }
                                            if (l7_info.has_protocol && c->l7_proto[0] == '\0') {
                                                strncpy(c->l7_proto, l7_info.protocol, sizeof(c->l7_proto) - 1);
                                                c->l7_proto[sizeof(c->l7_proto) - 1] = '\0';
                                            }
                                            if (l7_info.has_ja4 && c->ja4[0] == '\0') {
                                                snprintf(c->ja4, sizeof(c->ja4), "%s", l7_info.ja4);
                                            }
                                            if (l7_info.has_entropy) {
                                                c->entropy = l7_info.entropy;
                                                c->is_suspicious_entropy = l7_info.is_suspicious_entropy ? 1 : 0;
                                            }
                                        }

                                        /* QUIC & HTTP/3 Inspection (UDP port 443) */
                                        if (p.key.proto == NETCAP_PROTO_UDP && p.key.dst_port == 443 && c->domain_name[0] == '\0') {
                                            netcap_quic_info_t qinfo;
                                            if (netcap_quic_inspect(payload, payload_len, &qinfo)) {
                                                if (qinfo.has_sni) {
                                                    strncpy(c->domain_name, qinfo.domain, sizeof(c->domain_name) - 1);
                                                    c->domain_name[sizeof(c->domain_name) - 1] = '\0';
                                                }
                                                strncpy(c->l7_proto, "QUIC", sizeof(c->l7_proto) - 1);
                                                c->l7_proto[sizeof(c->l7_proto) - 1] = '\0';
                                            }
                                        }

                                        /* Shannon Entropy / DNS Tunneling Threat Check */
                                        if (e->threats && e->on_threat && c->domain_name[0] != '\0') {
                                            netcap_threat_alert_t alert;
                                            if (netcap_threat_inspect_dns(e->threats, c->uid, c->domain_name, &alert)) {
                                                e->on_threat(&alert, e->threat_user_data);
                                            }
                                        }
                                    }

                                    /* In-App payload buffering */
                                    if (e->cfg.payload_mode != NETCAP_PAYLOAD_NONE && p.l4_len > p.l4_hdr_len) {
                                        if (!c->payload_buf) {
                                            c->payload_buf = netcap_payload_buf_create((netcap_payload_mode_t)e->cfg.payload_mode);
                                        }
                                        if (c->payload_buf) {
                                            netcap_payload_buf_append((netcap_payload_buf_t *)c->payload_buf,
                                                                      p.is_outbound,
                                                                      p.l4 + p.l4_hdr_len,
                                                                      p.l4_len - p.l4_hdr_len,
                                                                      (uint64_t)now * 1000);
                                        }
                                    }

                                    if (batch_n < UPDATE_BATCH_MAX) batch[batch_n++] = c;
                                }

                                /* Forward traffic (both UDP and TCP) through the forward engine */
                                if (e->fwd) {
                                    if (p.key.proto == NETCAP_PROTO_UDP) {
                                        if (e->socks5_enabled && p.key.dst_port != 53 && p.key.dst_port != 5353) {
                                            /* Drop non-DNS UDP when SOCKS5 exit routing is enabled to force TCP and prevent QUIC leak */
                                        } else {
                                            netcap_forward_handle_udp(e->fwd, &p.key, buf, (uint32_t)n,
                                                                      p.ip_hdr_len, p.l4_hdr_len, orig_dst_ip);
                                        }
                                    } else if (p.key.proto == NETCAP_PROTO_TCP) {
                                        netcap_forward_handle_tcp(e->fwd, &p.key, buf, (uint32_t)n,
                                                                   p.ip_hdr_len, p.l4_hdr_len,
                                                                   p.tcp_flags, p.tcp_seq, p.tcp_ack);
                                    } else if (p.key.proto == 1 /* ICMP */ && p.key.family == 4) {
                                        netcap_forward_handle_icmp(e->fwd, &p.key, buf, (uint32_t)n, p.ip_hdr_len);
                                    }
                                }

                                if (e->dump) {
                                    pthread_mutex_lock(&e->dump_lock);
                                    if (e->dump) {
                                        struct timespec ts;
                                        clock_gettime(CLOCK_REALTIME, &ts);
                                        uint64_t ts_us = (uint64_t)ts.tv_sec * 1000000ull + ts.tv_nsec / 1000;
                                        netcap_pcapng_write_packet(e->dump, ts_us, buf, (uint32_t)n, (uint32_t)n);
                                    }
                                    pthread_mutex_unlock(&e->dump_lock);
                                }

                                /* Broadcast to live PCAPng HTTP streaming server if active */
                                if (e->stream_srv) {
                                    struct timespec ts;
                                    clock_gettime(CLOCK_REALTIME, &ts);
                                    uint64_t ts_us = (uint64_t)ts.tv_sec * 1000000ull + ts.tv_nsec / 1000;
                                    netcap_stream_server_poll(e->stream_srv);
                                    netcap_stream_server_broadcast(e->stream_srv, ts_us, buf, (uint32_t)n);
                                }
                            }
                        }
                    }
                }

        /* 2. ALWAYS drain UDP and TCP replies from remote servers on EVERY iteration */
        if (e->fwd) {
            netcap_forward_poll_replies(e->fwd);
        }

        /* 3. Flush batch updates and sweep idle connections periodically */
        if (now - last_sweep >= 1) {
            if (batch_n > 0 && e->on_update) {
                e->on_update(batch, batch_n, e->update_user_data);
                batch_n = 0;
            }
            netcap_conn_table_sweep_idle(e->conns, now, e->cfg.idle_timeout_secs);
            if (e->fwd) netcap_forward_sweep_idle(e->fwd, e->cfg.idle_timeout_secs);
            if (e->dump) {
                pthread_mutex_lock(&e->dump_lock);
                if (e->dump) netcap_pcapng_flush(e->dump);
                pthread_mutex_unlock(&e->dump_lock);
            }
            last_sweep = now;
        }
    }

    if (batch_n > 0 && e->on_update) e->on_update(batch, batch_n, e->update_user_data);
    return NULL;
}

int netcap_engine_start(netcap_engine_t *e, int tun_fd,
                         netcap_conn_update_cb on_update, void *user_data) {
    if (e->running) return -1;
    e->tun_fd = tun_fd;
    if (e->tun_fd >= 0) {
        int fl = fcntl(e->tun_fd, F_GETFL, 0);
        if (fl >= 0) fcntl(e->tun_fd, F_SETFL, fl | O_NONBLOCK);
    }
    e->on_update = on_update;
    e->update_user_data = user_data;
    e->running = 1;
    if (pthread_create(&e->worker, NULL, worker_main, e) != 0) {
        e->running = 0;
        return -1;
    }
    return 0;
}

void netcap_engine_stop(netcap_engine_t *e) {
    if (!e || !e->running) return;
    e->running = 0;
    if (e->tun_fd >= 0) {
        shutdown(e->tun_fd, SHUT_RDWR);
    }
    pthread_join(e->worker, NULL);
}

int netcap_engine_set_pcap_dump(netcap_engine_t *e, const char *path) {
    pthread_mutex_lock(&e->dump_lock);
    if (e->dump) { netcap_pcapng_close(e->dump); e->dump = NULL; }
    int rc = 0;
    if (path) {
        e->dump = netcap_pcapng_open(path, "tun0", e->cfg.snaplen);
        if (e->dump) {
            if (e->secrets) {
                netcap_secrets_dump_all_to_file(e->secrets, netcap_pcapng_get_fp(e->dump));
            }
        } else {
            rc = -1;
        }
    }
    pthread_mutex_unlock(&e->dump_lock);
    return rc;
}

void netcap_engine_attach_forward(netcap_engine_t *e, netcap_forward_engine_t *fwd) {
    if (!e) return;
    e->fwd = fwd;
    if (fwd) {
        netcap_forward_set_engine(fwd, e);
        if (e->socks5_enabled) {
            netcap_forward_set_socks5_proxy(fwd, e->socks5_proxy_ip, e->socks5_proxy_port);
        }
    }
}

void netcap_engine_record_reply(netcap_engine_t *e, const netcap_flow_key_t *key, uint32_t bytes) {
    if (!e || bytes == 0) return;
    pthread_mutex_lock(&e->stats_lock);
    e->stats.pkts_rcvd++;
    e->stats.bytes_rcvd += (uint64_t)bytes;
    pthread_mutex_unlock(&e->stats_lock);

    if (e->conns && key) {
        netcap_conn_t *c = netcap_conn_table_touch(e->conns, key, time(NULL));
        if (c) {
            c->bytes_rcvd += (uint64_t)bytes;
            c->pkts_rcvd++;
            c->last_seen = time(NULL);
        }
    }
}

void netcap_engine_set_uid_resolver(netcap_engine_t *e, netcap_uid_resolver_cb cb, void *user_data) {
    if (!e) return;
    e->uid_resolver = cb;
    e->uid_user_data = user_data;
}

netcap_blacklist_t *netcap_engine_get_blacklist(netcap_engine_t *e) { return e->blacklist; }
netcap_ring_log_t *netcap_engine_get_log(netcap_engine_t *e) { return &e->log; }
const netcap_conn_table_t *netcap_engine_get_conn_table(netcap_engine_t *e) { return e->conns; }

void netcap_engine_get_stats(const netcap_engine_t *e, netcap_engine_stats_t *out) {
    pthread_mutex_lock((pthread_mutex_t *)&e->stats_lock);
    *out = e->stats;
    pthread_mutex_unlock((pthread_mutex_t *)&e->stats_lock);
    out->active_connections = netcap_conn_table_count(e->conns);
}

static void on_stream_client_connected(int client_fd, void *user_data) {
    netcap_engine_t *e = (netcap_engine_t *)user_data;
    if (e && e->secrets) {
        netcap_secrets_dump_all_to_fd(e->secrets, client_fd);
    }
}

int netcap_engine_start_stream_server(netcap_engine_t *e, uint16_t port) {
    if (!e) return -1;
    if (e->stream_srv) netcap_stream_server_destroy(e->stream_srv);
    e->stream_srv = netcap_stream_server_create(port);
    if (e->stream_srv) {
        netcap_stream_server_set_client_connect_cb(e->stream_srv, on_stream_client_connected, e);
    }
    return e->stream_srv ? 0 : -1;
}

void netcap_engine_stop_stream_server(netcap_engine_t *e) {
    if (!e || !e->stream_srv) return;
    netcap_stream_server_destroy(e->stream_srv);
    e->stream_srv = NULL;
}

uint32_t netcap_engine_get_conn_payload(netcap_engine_t *e, const netcap_flow_key_t *key,
                                        int dir, uint8_t *out_buf, uint32_t max_len) {
    if (!e || !e->conns || !key || !out_buf || max_len == 0) return 0;
    netcap_conn_t *c = netcap_conn_table_touch(e->conns, key, time(NULL));
    if (!c || !c->payload_buf) return 0;
    return netcap_payload_buf_get((const netcap_payload_buf_t *)c->payload_buf, dir, out_buf, max_len);
}

void netcap_engine_set_private_dns_blocked(netcap_engine_t *engine, bool blocked) {
    if (engine) netcap_dns_policy_set_block_dot(engine->dns_policy, blocked);
}

int netcap_engine_set_custom_dns(netcap_engine_t *engine, const char *dns_ip) {
    return engine ? netcap_dns_policy_set_custom_dns(engine->dns_policy, dns_ip) : -1;
}

void netcap_engine_set_lan_blocked_uids(netcap_engine_t *engine, const int32_t *uids, size_t count) {
    if (engine) netcap_dns_policy_set_lan_blocked_uids(engine->dns_policy, uids, (uint32_t)count);
}

int netcap_engine_add_proxy_rule(netcap_engine_t *engine, uint16_t orig_port, const char *target_ip, uint16_t target_port) {
    return engine ? netcap_proxy_relay_add_rule(engine->proxy_relay, NETCAP_PROTO_TCP, orig_port, target_port, target_ip) : -1;
}

int netcap_engine_remove_proxy_rule(netcap_engine_t *engine, uint16_t orig_port) {
    if (!engine) return -1;
    netcap_proxy_relay_remove_rule(engine->proxy_relay, NETCAP_PROTO_TCP, orig_port);
    return 0;
}

void netcap_engine_set_proxy_exempt_uid(netcap_engine_t *engine, int32_t uid) {
    if (engine) {
        int32_t u = uid;
        netcap_proxy_relay_set_exempt_uids(engine->proxy_relay, &u, (uid >= 0) ? 1 : 0);
    }
}

int netcap_engine_set_socks5_proxy(netcap_engine_t *engine, const char *proxy_ip, uint16_t proxy_port) {
    if (!engine) return -1;
    if (proxy_ip && proxy_port > 0) {
        strncpy(engine->socks5_proxy_ip, proxy_ip, sizeof(engine->socks5_proxy_ip) - 1);
        engine->socks5_proxy_ip[sizeof(engine->socks5_proxy_ip) - 1] = '\0';
        engine->socks5_proxy_port = proxy_port;
        engine->socks5_enabled = true;
    } else {
        engine->socks5_proxy_ip[0] = '\0';
        engine->socks5_proxy_port = 0;
        engine->socks5_enabled = false;
    }
    if (engine->fwd) {
        netcap_forward_set_socks5_proxy(engine->fwd, proxy_ip, proxy_port);
    }
    return 0;
}

int netcap_engine_add_tls_secret(netcap_engine_t *e, const char *keylog_line) {
    if (!e || !keylog_line) return -1;
    netcap_secrets_add_tls_key(e->secrets, keylog_line);

    /* Write to file dump if active */
    pthread_mutex_lock(&e->dump_lock);
    if (e->dump) {
        FILE *fp = netcap_pcapng_get_fp(e->dump);
        if (fp) {
            netcap_pcapng_write_dsb_file(fp, PCAPNG_DSB_SECRETS_TLS, (const uint8_t*)keylog_line, (uint32_t)strlen(keylog_line));
            fflush(fp);
        }
    }
    pthread_mutex_unlock(&e->dump_lock);

    /* Broadcast to streaming server clients if active */
    if (e->stream_srv) {
        uint8_t dsb_buf[2048];
        size_t blk_sz = netcap_pcapng_build_dsb(PCAPNG_DSB_SECRETS_TLS, (const uint8_t*)keylog_line, (uint32_t)strlen(keylog_line), dsb_buf, sizeof(dsb_buf));
        if (blk_sz <= sizeof(dsb_buf)) {
            netcap_stream_server_broadcast_raw(e->stream_srv, dsb_buf, blk_sz);
        }
    }
    return 0;
}

void netcap_engine_set_threat_callback(netcap_engine_t *engine, netcap_threat_alert_cb cb, void *user_data) {
    if (!engine) return;
    engine->on_threat = cb;
    engine->threat_user_data = user_data;
}

void netcap_engine_get_conn_speed(netcap_engine_t *engine, const netcap_flow_key_t *key,
                                  double *out_tx_bps, double *out_rx_bps) {
    if (out_tx_bps) *out_tx_bps = 0.0;
    if (out_rx_bps) *out_rx_bps = 0.0;
    if (!engine || !engine->conns || !key) return;

    netcap_conn_t *c = netcap_conn_table_touch(engine->conns, key, time(NULL));
    if (c) {
        if (out_tx_bps) *out_tx_bps = c->tx_bps;
        if (out_rx_bps) *out_rx_bps = c->rx_bps;
    }
}

bool netcap_engine_lookup_dns_cache(netcap_engine_t *engine, const uint8_t *ip, uint8_t family,
                                    char *out_domain, size_t max_len) {
    if (!engine || !engine->dns_cache) return false;
    return netcap_dns_cache_lookup(engine->dns_cache, ip, family, out_domain, max_len);
}

void netcap_engine_set_blocked_uids(netcap_engine_t *engine, const int32_t *uids, size_t count) {
    if (engine && engine->firewall) {
        netcap_firewall_set_blocked_uids(engine->firewall, uids, (uint32_t)count);
    }
}

void netcap_engine_add_blocked_domain(netcap_engine_t *engine, const char *domain) {
    if (engine && engine->firewall) {
        netcap_firewall_add_blocked_domain(engine->firewall, domain);
    }
}

void netcap_engine_remove_blocked_domain(netcap_engine_t *engine, const char *domain) {
    if (engine && engine->firewall) {
        netcap_firewall_remove_blocked_domain(engine->firewall, domain);
    }
}

void netcap_engine_clear_blocked_domains(netcap_engine_t *engine) {
    if (engine && engine->firewall) {
        netcap_firewall_clear_blocked_domains(engine->firewall);
    }
}

void netcap_engine_record_reply_data(netcap_engine_t *engine, const netcap_flow_key_t *key,
                                     const uint8_t *payload, uint32_t payload_len, uint32_t total_wire_bytes) {
    if (!engine) return;
    netcap_engine_record_reply(engine, key, total_wire_bytes);

    if (key && payload && payload_len >= 12) {
        if (key->dst_port == 53 || key->src_port == 53 || key->dst_port == 5353 || key->src_port == 5353) {
            if (engine->dns_cache) {
                netcap_dns_cache_learn_response(engine->dns_cache, payload, payload_len);
            }
            if (engine->conns) {
                netcap_conn_t *c = netcap_conn_table_touch(engine->conns, key, time(NULL));
                if (c && c->domain_name[0] == '\0') {
                    char qname[256] = {0};
                    if (netcap_dns_extract_qname(payload, payload_len, qname, sizeof(qname))) {
                        strncpy(c->domain_name, qname, sizeof(c->domain_name) - 1);
                        c->domain_name[sizeof(c->domain_name) - 1] = '\0';
                    }
                }
            }
        }
    }
}

