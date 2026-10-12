#define _POSIX_C_SOURCE 200809L
#include "forward.h"
#include "capture_engine.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

#define NETCAP_NIL_FWD UINT32_MAX
#define MAX_UDP_REPLY 65535
#define MAX_TCP_REPLY 4096

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/* --- UDP Flow State --- */
typedef struct {
    netcap_flow_key_t key;
    uint8_t reply_src_ip[16];
    int sock;
    time_t last_seen;
    uint8_t occupied;
    uint32_t hash_next;
} udp_flow_t;

/* --- TCP Flow State --- */
typedef enum {
    TCP_FLOW_CLOSED = 0,
    TCP_FLOW_CONNECTING,
    TCP_FLOW_SOCKS_CONNECTING,
    TCP_FLOW_SOCKS_GREETING_ACK,
    TCP_FLOW_SOCKS_CONNECT_ACK,
    TCP_FLOW_ESTABLISHED,
    TCP_FLOW_FIN_WAIT
} tcp_flow_state_t;

typedef struct {
    netcap_flow_key_t key;
    int sock;
    tcp_flow_state_t state;
    time_t last_seen;
    uint32_t client_seq;      /* Current client seq tracked */
    uint32_t server_seq;      /* Synthetic server seq tracked */
    uint8_t occupied;
    uint32_t hash_next;
} tcp_flow_t;

/* --- ICMPv4 Echo Flow State ---
 * Relayed through unprivileged ping sockets (SOCK_DGRAM/IPPROTO_ICMP), which
 * Android permits for regular apps. The kernel rewrites the echo identifier
 * to the socket's local id, so we remember the client's original id and
 * restore it on the reply path. */
#define MAX_ICMP_FLOWS 64
#define MAX_ICMP_REPLY 2048

typedef struct {
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint16_t echo_id;         /* client's original identifier (network order) */
    int sock;
    time_t last_seen;
    uint8_t occupied;
} icmp_flow_t;

struct netcap_forward_engine {
    int tun_fd;

    /* UDP flows */
    udp_flow_t *udp_flows;
    uint32_t udp_capacity;
    uint32_t *udp_buckets;
    uint32_t udp_bucket_mask;
    uint32_t udp_free_head;
    uint32_t udp_count;

    /* TCP flows */
    tcp_flow_t *tcp_flows;
    uint32_t tcp_capacity;
    uint32_t *tcp_buckets;
    uint32_t tcp_bucket_mask;
    uint32_t tcp_free_head;
    uint32_t tcp_count;

    netcap_protect_fd_cb protect_cb;
    void *protect_user_data;

    netcap_tcp_backend_t tcp_backend; /* optional external backend */

    icmp_flow_t icmp_flows[MAX_ICMP_FLOWS];

    /* SOCKS5 proxy configuration */
    uint8_t socks5_ip[16];
    uint8_t socks5_family; /* 4 or 6, or 0 if disabled */
    uint16_t socks5_port;  /* 0 if disabled */

    void *engine; /* netcap_engine_t pointer for stats/conn tracking */
};

static uint32_t fwd_hash(const netcap_flow_key_t *k) {
    uint32_t h = 2166136261u;
    const uint8_t *p = (const uint8_t *)k;
    for (size_t i = 0; i < sizeof(*k); i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static uint32_t next_pow2(uint32_t n) { uint32_t p = 1; while (p < n) p <<= 1; return p; }

static uint16_t ip_checksum(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum_v4(const uint8_t src_ip[4], const uint8_t dst_ip[4],
                                const uint8_t *tcp_seg, uint16_t tcp_len) {
    uint32_t sum = 0;
    const uint16_t *p;

    /* Pseudo-header */
    p = (const uint16_t *)src_ip;
    sum += p[0]; sum += p[1];

    p = (const uint16_t *)dst_ip;
    sum += p[0]; sum += p[1];

    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    /* TCP segment */
    p = (const uint16_t *)tcp_seg;
    uint32_t count = tcp_len;
    while (count > 1) {
        sum += *p++;
        count -= 2;
    }
    if (count > 0) {
        uint8_t last[2] = { *(const uint8_t *)p, 0 };
        sum += *(const uint16_t *)last;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint32_t csum_add(uint32_t sum, const uint8_t *data, uint32_t len);
static uint16_t csum_fold(uint32_t sum);

netcap_forward_engine_t *netcap_forward_create(int tun_fd) {
    netcap_forward_engine_t *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->tun_fd = tun_fd;

    /* Setup UDP table */
    f->udp_capacity = 512;
    f->udp_flows = calloc(f->udp_capacity, sizeof(udp_flow_t));
    uint32_t udp_nbuckets = next_pow2(f->udp_capacity + f->udp_capacity / 3 + 1);
    f->udp_bucket_mask = udp_nbuckets - 1;
    f->udp_buckets = malloc(udp_nbuckets * sizeof(uint32_t));
    if (!f->udp_flows || !f->udp_buckets) {
        netcap_forward_destroy(f);
        return NULL;
    }
    for (uint32_t i = 0; i < udp_nbuckets; i++) f->udp_buckets[i] = NETCAP_NIL_FWD;
    for (uint32_t i = 0; i < f->udp_capacity; i++) f->udp_flows[i].hash_next = (i + 1 < f->udp_capacity) ? i + 1 : NETCAP_NIL_FWD;
    f->udp_free_head = 0;

    /* Setup TCP table */
    f->tcp_capacity = 512;
    f->tcp_flows = calloc(f->tcp_capacity, sizeof(tcp_flow_t));
    uint32_t tcp_nbuckets = next_pow2(f->tcp_capacity + f->tcp_capacity / 3 + 1);
    f->tcp_bucket_mask = tcp_nbuckets - 1;
    f->tcp_buckets = malloc(tcp_nbuckets * sizeof(uint32_t));
    if (!f->tcp_flows || !f->tcp_buckets) {
        netcap_forward_destroy(f);
        return NULL;
    }
    for (uint32_t i = 0; i < tcp_nbuckets; i++) f->tcp_buckets[i] = NETCAP_NIL_FWD;
    for (uint32_t i = 0; i < f->tcp_capacity; i++) f->tcp_flows[i].hash_next = (i + 1 < f->tcp_capacity) ? i + 1 : NETCAP_NIL_FWD;
    f->tcp_free_head = 0;

    for (uint32_t i = 0; i < MAX_ICMP_FLOWS; i++) f->icmp_flows[i].sock = -1;

    return f;
}

static void close_udp_flow_slot(netcap_forward_engine_t *f, uint32_t idx) {
    udp_flow_t *s = &f->udp_flows[idx];
    if (s->sock >= 0) close(s->sock);
    uint32_t bucket = fwd_hash(&s->key) & f->udp_bucket_mask;
    uint32_t cur = f->udp_buckets[bucket], prev = NETCAP_NIL_FWD;
    while (cur != NETCAP_NIL_FWD) {
        if (cur == idx) {
            if (prev == NETCAP_NIL_FWD) f->udp_buckets[bucket] = f->udp_flows[cur].hash_next;
            else f->udp_flows[prev].hash_next = f->udp_flows[cur].hash_next;
            break;
        }
        prev = cur; cur = f->udp_flows[cur].hash_next;
    }
    memset(s, 0, sizeof(*s));
    s->hash_next = f->udp_free_head;
    f->udp_free_head = idx;
    f->udp_count--;
}

static void close_tcp_flow_slot(netcap_forward_engine_t *f, uint32_t idx) {
    tcp_flow_t *s = &f->tcp_flows[idx];
    if (s->sock >= 0) close(s->sock);
    uint32_t bucket = fwd_hash(&s->key) & f->tcp_bucket_mask;
    uint32_t cur = f->tcp_buckets[bucket], prev = NETCAP_NIL_FWD;
    while (cur != NETCAP_NIL_FWD) {
        if (cur == idx) {
            if (prev == NETCAP_NIL_FWD) f->tcp_buckets[bucket] = f->tcp_flows[cur].hash_next;
            else f->tcp_flows[prev].hash_next = f->tcp_flows[cur].hash_next;
            break;
        }
        prev = cur; cur = f->tcp_flows[cur].hash_next;
    }
    memset(s, 0, sizeof(*s));
    s->hash_next = f->tcp_free_head;
    f->tcp_free_head = idx;
    f->tcp_count--;
}

void netcap_forward_destroy(netcap_forward_engine_t *f) {
    if (!f) return;
    if (f->udp_flows) {
        for (uint32_t i = 0; i < f->udp_capacity; i++) {
            if (f->udp_flows[i].occupied && f->udp_flows[i].sock >= 0) close(f->udp_flows[i].sock);
        }
        free(f->udp_flows);
    }
    free(f->udp_buckets);

    if (f->tcp_flows) {
        for (uint32_t i = 0; i < f->tcp_capacity; i++) {
            if (f->tcp_flows[i].occupied && f->tcp_flows[i].sock >= 0) close(f->tcp_flows[i].sock);
        }
        free(f->tcp_flows);
    }
    free(f->tcp_buckets);

    for (uint32_t i = 0; i < MAX_ICMP_FLOWS; i++) {
        if (f->icmp_flows[i].occupied && f->icmp_flows[i].sock >= 0) close(f->icmp_flows[i].sock);
    }

    free(f);
}

void netcap_forward_set_protect_cb(netcap_forward_engine_t *f,
                                    netcap_protect_fd_cb cb, void *user_data) {
    f->protect_cb = cb;
    f->protect_user_data = user_data;
}

void netcap_forward_set_engine(netcap_forward_engine_t *f, void *engine) {
    if (!f) return;
    f->engine = engine;
}

void netcap_forward_set_tcp_backend(netcap_forward_engine_t *f,
                                     const netcap_tcp_backend_t *backend) {
    if (backend) f->tcp_backend = *backend;
    else memset(&f->tcp_backend, 0, sizeof(f->tcp_backend));
}

void netcap_forward_set_socks5_proxy(netcap_forward_engine_t *f, const char *proxy_ip, uint16_t proxy_port) {
    if (!f) return;
    if (!proxy_ip || proxy_port == 0) {
        f->socks5_port = 0;
        f->socks5_family = 0;
        memset(f->socks5_ip, 0, sizeof(f->socks5_ip));
        return;
    }
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, proxy_ip, &a4) == 1) {
        f->socks5_family = 4;
        f->socks5_port = proxy_port;
        memset(f->socks5_ip, 0, sizeof(f->socks5_ip));
        memcpy(f->socks5_ip, &a4.s_addr, 4);
    } else if (inet_pton(AF_INET6, proxy_ip, &a6) == 1) {
        f->socks5_family = 6;
        f->socks5_port = proxy_port;
        memcpy(f->socks5_ip, &a6.s6_addr, 16);
    } else {
        f->socks5_port = 0;
        f->socks5_family = 0;
    }
}

/* --- UDP Engine Functions --- */

static udp_flow_t *find_udp_flow(netcap_forward_engine_t *f, const netcap_flow_key_t *key) {
    uint32_t bucket = fwd_hash(key) & f->udp_bucket_mask;
    uint32_t cur = f->udp_buckets[bucket];
    while (cur != NETCAP_NIL_FWD) {
        if (f->udp_flows[cur].occupied && memcmp(&f->udp_flows[cur].key, key, sizeof(*key)) == 0)
            return &f->udp_flows[cur];
        cur = f->udp_flows[cur].hash_next;
    }
    return NULL;
}

static udp_flow_t *create_udp_flow(netcap_forward_engine_t *f, const netcap_flow_key_t *key, const uint8_t *reply_src_ip) {
    if (f->udp_free_head == NETCAP_NIL_FWD) {
        for (uint32_t i = 0; i < f->udp_capacity; i++) {
            if (f->udp_flows[i].occupied) { close_udp_flow_slot(f, i); break; }
        }
        if (f->udp_free_head == NETCAP_NIL_FWD) return NULL;
    }

    int family = (key->family == 4) ? AF_INET : AF_INET6;
    int sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return NULL;
    fcntl(sock, F_SETFL, O_NONBLOCK);

    if (f->protect_cb && f->protect_cb(sock, f->protect_user_data) != 0) {
        close(sock);
        return NULL;
    }

    struct sockaddr_storage dst = {0};
    socklen_t dst_len;
    if (key->family == 4) {
        struct sockaddr_in *d = (struct sockaddr_in *)&dst;
        d->sin_family = AF_INET;
        d->sin_port = htons(key->dst_port);
        memcpy(&d->sin_addr, key->dst_ip, 4);
        dst_len = sizeof(*d);
    } else {
        struct sockaddr_in6 *d = (struct sockaddr_in6 *)&dst;
        d->sin6_family = AF_INET6;
        d->sin6_port = htons(key->dst_port);
        memcpy(&d->sin6_addr, key->dst_ip, 16);
        dst_len = sizeof(*d);
    }
    if (connect(sock, (struct sockaddr *)&dst, dst_len) != 0) {
        close(sock);
        return NULL;
    }

    uint32_t idx = f->udp_free_head;
    f->udp_free_head = f->udp_flows[idx].hash_next;
    udp_flow_t *s = &f->udp_flows[idx];
    memset(s, 0, sizeof(*s));
    s->key = *key;
    if (reply_src_ip) {
        memcpy(s->reply_src_ip, reply_src_ip, (key->family == 4) ? 4 : 16);
    } else {
        memcpy(s->reply_src_ip, key->dst_ip, (key->family == 4) ? 4 : 16);
    }
    s->sock = sock;
    s->last_seen = time(NULL);
    s->occupied = 1;

    uint32_t bucket = fwd_hash(key) & f->udp_bucket_mask;
    s->hash_next = f->udp_buckets[bucket];
    f->udp_buckets[bucket] = idx;
    f->udp_count++;
    return s;
}

int netcap_forward_handle_udp(netcap_forward_engine_t *f,
                               const netcap_flow_key_t *key,
                               const uint8_t *full_packet, uint32_t packet_len,
                               uint32_t ip_hdr_len, uint32_t udp_hdr_len,
                               const uint8_t *reply_src_ip) {
    if (packet_len < ip_hdr_len + udp_hdr_len) return -1;
    const uint8_t *payload = full_packet + ip_hdr_len + udp_hdr_len;
    uint32_t payload_len = packet_len - ip_hdr_len - udp_hdr_len;

    udp_flow_t *flow = find_udp_flow(f, key);
    if (!flow) flow = create_udp_flow(f, key, reply_src_ip);
    if (!flow) return -1;

    flow->last_seen = time(NULL);
    ssize_t sent = send(flow->sock, payload, payload_len, 0);
    return (sent >= 0) ? 0 : -1;
}

static void write_reply_v4_udp(netcap_forward_engine_t *f, const udp_flow_t *s,
                               const uint8_t *payload, uint32_t payload_len) {
    uint8_t pkt[20 + 8 + MAX_UDP_REPLY];
    if (payload_len > MAX_UDP_REPLY) payload_len = MAX_UDP_REPLY;
    uint32_t udp_len = 8 + payload_len;
    uint32_t total_len = 20 + udp_len;

    uint8_t *ip = pkt;
    memset(ip, 0, 20);
    ip[0] = 0x45;                       /* version 4, IHL 5 */
    ip[2] = (uint8_t)(total_len >> 8);  ip[3] = (uint8_t)total_len;
    ip[6] = 0x40;                       /* don't fragment */
    ip[8] = 64;                         /* TTL */
    ip[9] = IPPROTO_UDP;                /* UDP */
    memcpy(ip + 12, s->reply_src_ip, 4); /* reply src = original destination (e.g. 10.215.173.2) */
    memcpy(ip + 16, s->key.src_ip, 4);   /* reply dst = original client */
    uint16_t csum = ip_checksum(ip, 20);
    memcpy(ip + 10, &csum, 2);

    uint8_t *udp = pkt + 20;
    uint16_t sp = htons(s->key.dst_port), dp = htons(s->key.src_port), ul = htons((uint16_t)udp_len);
    memcpy(udp, &sp, 2); memcpy(udp + 2, &dp, 2);
    memcpy(udp + 4, &ul, 2);
    udp[6] = 0; udp[7] = 0;
    memcpy(udp + 8, payload, payload_len);

    if (f->tun_fd >= 0) write(f->tun_fd, pkt, total_len);
    if (f->engine) netcap_engine_record_reply_data((netcap_engine_t *)f->engine, &s->key, payload, payload_len, total_len);
}

static void write_reply_v6_udp(netcap_forward_engine_t *f, const udp_flow_t *s,
                               const uint8_t *payload, uint32_t payload_len) {
    uint8_t pkt[40 + 8 + MAX_UDP_REPLY];
    if (payload_len > MAX_UDP_REPLY) payload_len = MAX_UDP_REPLY;
    uint32_t udp_len = 8 + payload_len;
    uint32_t total_len = 40 + udp_len;

    uint8_t *ip = pkt;
    memset(ip, 0, 40);
    ip[0] = 0x60;                       /* IPv6 */
    ip[4] = (uint8_t)(udp_len >> 8); ip[5] = (uint8_t)udp_len;
    ip[6] = IPPROTO_UDP;
    ip[7] = 64;                         /* Hop limit */
    memcpy(ip + 8, s->reply_src_ip, 16);
    memcpy(ip + 24, s->key.src_ip, 16);

    uint8_t *udp = pkt + 40;
    uint16_t sp = htons(s->key.dst_port), dp = htons(s->key.src_port), ul = htons((uint16_t)udp_len);
    memcpy(udp, &sp, 2); memcpy(udp + 2, &dp, 2);
    memcpy(udp + 4, &ul, 2);
    udp[6] = 0; udp[7] = 0;
    memcpy(udp + 8, payload, payload_len);

    /* IPv6 forbids a zero UDP checksum (RFC 8200 s8.1) */
    uint8_t ph[8] = { 0, 0, (uint8_t)(udp_len >> 8), (uint8_t)udp_len, 0, 0, 0, IPPROTO_UDP };
    uint32_t sum = csum_add(0, ip + 8, 32);
    sum = csum_add(sum, ph, 8);
    sum = csum_add(sum, udp, udp_len);
    uint16_t ucsum = csum_fold(sum);
    if (ucsum == 0) ucsum = 0xFFFF;
    memcpy(udp + 6, &ucsum, 2);

    if (f->tun_fd >= 0) write(f->tun_fd, pkt, total_len);
    if (f->engine) netcap_engine_record_reply_data((netcap_engine_t *)f->engine, &s->key, payload, payload_len, total_len);
}

/* --- ICMPv4 Echo Engine Functions --- */

static void close_icmp_flow(icmp_flow_t *s) {
    if (s->sock >= 0) close(s->sock);
    memset(s, 0, sizeof(*s));
    s->sock = -1;
}

static icmp_flow_t *get_icmp_flow(netcap_forward_engine_t *f, const uint8_t src[4],
                                  const uint8_t dst[4], uint16_t echo_id) {
    icmp_flow_t *free_slot = NULL, *oldest = NULL;
    for (uint32_t i = 0; i < MAX_ICMP_FLOWS; i++) {
        icmp_flow_t *s = &f->icmp_flows[i];
        if (!s->occupied) { if (!free_slot) free_slot = s; continue; }
        if (s->echo_id == echo_id && memcmp(s->src_ip, src, 4) == 0 && memcmp(s->dst_ip, dst, 4) == 0)
            return s;
        if (!oldest || s->last_seen < oldest->last_seen) oldest = s;
    }
    if (!free_slot) { close_icmp_flow(oldest); free_slot = oldest; }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) return NULL;
    fcntl(sock, F_SETFL, O_NONBLOCK);
    if (f->protect_cb && f->protect_cb(sock, f->protect_user_data) != 0) {
        close(sock);
        return NULL;
    }
    struct sockaddr_in d = {0};
    d.sin_family = AF_INET;
    memcpy(&d.sin_addr, dst, 4);
    if (connect(sock, (struct sockaddr *)&d, sizeof(d)) != 0) {
        close(sock);
        return NULL;
    }

    memcpy(free_slot->src_ip, src, 4);
    memcpy(free_slot->dst_ip, dst, 4);
    free_slot->echo_id = echo_id;
    free_slot->sock = sock;
    free_slot->last_seen = time(NULL);
    free_slot->occupied = 1;
    return free_slot;
}

int netcap_forward_handle_icmp(netcap_forward_engine_t *f,
                                const netcap_flow_key_t *key,
                                const uint8_t *full_packet, uint32_t packet_len,
                                uint32_t ip_hdr_len) {
    if (key->family != 4 || packet_len < ip_hdr_len + 8) return -1;
    const uint8_t *icmp = full_packet + ip_hdr_len;
    uint32_t icmp_len = packet_len - ip_hdr_len;
    if (icmp[0] != 8 /* echo request */) return -1;

    uint16_t echo_id;
    memcpy(&echo_id, icmp + 4, 2);
    icmp_flow_t *s = get_icmp_flow(f, key->src_ip, key->dst_ip, echo_id);
    if (!s) return -1;
    s->last_seen = time(NULL);

    /* Kernel fills in identifier and checksum for ping sockets */
    ssize_t sent = send(s->sock, icmp, icmp_len, 0);
    return (sent >= 0) ? 0 : -1;
}

static void write_reply_v4_icmp(netcap_forward_engine_t *f, const icmp_flow_t *s,
                                uint8_t *icmp, uint32_t icmp_len) {
    uint8_t pkt[20 + MAX_ICMP_REPLY];
    if (icmp_len > MAX_ICMP_REPLY || icmp_len < 8) return;

    /* Restore client's identifier and recompute ICMP checksum */
    memcpy(icmp + 4, &s->echo_id, 2);
    icmp[2] = 0; icmp[3] = 0;
    uint16_t icsum = ip_checksum(icmp, icmp_len);
    memcpy(icmp + 2, &icsum, 2);

    uint32_t total_len = 20 + icmp_len;
    uint8_t *ip = pkt;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    ip[2] = (uint8_t)(total_len >> 8); ip[3] = (uint8_t)total_len;
    ip[8] = 64;
    ip[9] = IPPROTO_ICMP;
    memcpy(ip + 12, s->dst_ip, 4);
    memcpy(ip + 16, s->src_ip, 4);
    uint16_t csum = ip_checksum(ip, 20);
    memcpy(ip + 10, &csum, 2);
    memcpy(pkt + 20, icmp, icmp_len);

    if (f->tun_fd >= 0) write(f->tun_fd, pkt, total_len);
    if (f->engine) {
        netcap_flow_key_t key = {0};
        key.family = 4;
        key.proto = 1; /* ICMP */
        memcpy(key.src_ip, s->src_ip, 4);
        memcpy(key.dst_ip, s->dst_ip, 4);
        netcap_engine_record_reply((netcap_engine_t *)f->engine, &key, total_len);
    }
}

/* --- TCP Engine Functions --- */

static tcp_flow_t *find_tcp_flow(netcap_forward_engine_t *f, const netcap_flow_key_t *key) {
    uint32_t bucket = fwd_hash(key) & f->tcp_bucket_mask;
    uint32_t cur = f->tcp_buckets[bucket];
    while (cur != NETCAP_NIL_FWD) {
        if (f->tcp_flows[cur].occupied && memcmp(&f->tcp_flows[cur].key, key, sizeof(*key)) == 0)
            return &f->tcp_flows[cur];
        cur = f->tcp_flows[cur].hash_next;
    }
    return NULL;
}

static void write_tcp_v4(netcap_forward_engine_t *f, const netcap_flow_key_t *key,
                         uint8_t flags, uint32_t seq, uint32_t ack,
                         const uint8_t *payload, uint32_t payload_len) {
    uint8_t pkt[20 + 24 + MAX_TCP_REPLY];
    if (payload_len > MAX_TCP_REPLY) payload_len = MAX_TCP_REPLY;
    uint32_t tcp_hdr_len = (flags & TCP_FLAG_SYN) ? 24 : 20;
    uint32_t tcp_len = tcp_hdr_len + payload_len;
    uint32_t total_len = 20 + tcp_len;

    /* IPv4 header */
    uint8_t *ip = pkt;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    ip[2] = (uint8_t)(total_len >> 8); ip[3] = (uint8_t)total_len;
    ip[6] = 0x40;                       /* DF */
    ip[8] = 64;                         /* TTL */
    ip[9] = IPPROTO_TCP;                /* TCP */
    memcpy(ip + 12, key->dst_ip, 4);    /* src = remote server */
    memcpy(ip + 16, key->src_ip, 4);    /* dst = client app */
    uint16_t ipcsum = ip_checksum(ip, 20);
    memcpy(ip + 10, &ipcsum, 2);

    /* TCP header */
    uint8_t *tcp = pkt + 20;
    memset(tcp, 0, tcp_hdr_len);
    uint16_t sp = htons(key->dst_port);
    uint16_t dp = htons(key->src_port);
    memcpy(tcp, &sp, 2);
    memcpy(tcp + 2, &dp, 2);

    uint32_t n_seq = htonl(seq);
    uint32_t n_ack = htonl(ack);
    memcpy(tcp + 4, &n_seq, 4);
    memcpy(tcp + 8, &n_ack, 4);
    tcp[12] = (uint8_t)((tcp_hdr_len / 4) << 4); /* data offset */
    tcp[13] = flags;
    uint16_t win = htons(65535);
    memcpy(tcp + 14, &win, 2);

    if (flags & TCP_FLAG_SYN) {
        /* MSS Option: Kind 2, Len 4, Value 1400 (0x0578) */
        tcp[20] = 0x02;
        tcp[21] = 0x04;
        tcp[22] = (uint8_t)(1400 >> 8);
        tcp[23] = (uint8_t)(1400 & 0xFF);
    }

    if (payload && payload_len > 0) {
        memcpy(pkt + 20 + tcp_hdr_len, payload, payload_len);
    }

    uint16_t tcpcsum = tcp_checksum_v4(key->dst_ip, key->src_ip, tcp, (uint16_t)tcp_len);
    memcpy(tcp + 16, &tcpcsum, 2);

    if (f->tun_fd >= 0) write(f->tun_fd, pkt, total_len);
    if (f->engine) netcap_engine_record_reply((netcap_engine_t *)f->engine, key, total_len);
}

static uint32_t csum_add(uint32_t sum, const uint8_t *data, uint32_t len) {
    while (len > 1) { sum += ((uint32_t)data[0] << 8) | data[1]; data += 2; len -= 2; }
    if (len) sum += (uint32_t)data[0] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static void write_tcp_v6(netcap_forward_engine_t *f, const netcap_flow_key_t *key,
                         uint8_t flags, uint32_t seq, uint32_t ack,
                         const uint8_t *payload, uint32_t payload_len) {
    uint8_t pkt[40 + 24 + MAX_TCP_REPLY];
    if (payload_len > MAX_TCP_REPLY) payload_len = MAX_TCP_REPLY;
    uint32_t tcp_hdr_len = (flags & TCP_FLAG_SYN) ? 24 : 20;
    uint32_t tcp_len = tcp_hdr_len + payload_len;
    uint32_t total_len = 40 + tcp_len;

    /* IPv6 header */
    uint8_t *ip = pkt;
    memset(ip, 0, 40);
    ip[0] = 0x60;
    ip[4] = (uint8_t)(tcp_len >> 8); ip[5] = (uint8_t)tcp_len;
    ip[6] = IPPROTO_TCP;
    ip[7] = 64;                         /* hop limit */
    memcpy(ip + 8, key->dst_ip, 16);    /* src = remote server */
    memcpy(ip + 24, key->src_ip, 16);   /* dst = client app */

    /* TCP header */
    uint8_t *tcp = pkt + 40;
    memset(tcp, 0, tcp_hdr_len);
    uint16_t sp = htons(key->dst_port), dp = htons(key->src_port);
    memcpy(tcp, &sp, 2);
    memcpy(tcp + 2, &dp, 2);
    uint32_t n_seq = htonl(seq), n_ack = htonl(ack);
    memcpy(tcp + 4, &n_seq, 4);
    memcpy(tcp + 8, &n_ack, 4);
    tcp[12] = (uint8_t)((tcp_hdr_len / 4) << 4);
    tcp[13] = flags;
    uint16_t win = htons(65535);
    memcpy(tcp + 14, &win, 2);
    if (flags & TCP_FLAG_SYN) {
        tcp[20] = 0x02; tcp[21] = 0x04;
        tcp[22] = (uint8_t)(1400 >> 8); tcp[23] = (uint8_t)(1400 & 0xFF);
    }
    if (payload && payload_len > 0) memcpy(tcp + tcp_hdr_len, payload, payload_len);

    /* Pseudo-header: src, dst, upper-layer length (32-bit), next header (32-bit) */
    uint8_t ph[8] = { 0, 0, (uint8_t)(tcp_len >> 8), (uint8_t)tcp_len, 0, 0, 0, IPPROTO_TCP };
    uint32_t sum = csum_add(0, ip + 8, 32);
    sum = csum_add(sum, ph, 8);
    sum = csum_add(sum, tcp, tcp_len);
    uint16_t tcpcsum = csum_fold(sum);
    memcpy(tcp + 16, &tcpcsum, 2);

    if (f->tun_fd >= 0) write(f->tun_fd, pkt, total_len);
    if (f->engine) netcap_engine_record_reply((netcap_engine_t *)f->engine, key, total_len);
}

static void write_tcp(netcap_forward_engine_t *f, const netcap_flow_key_t *key,
                      uint8_t flags, uint32_t seq, uint32_t ack,
                      const uint8_t *payload, uint32_t payload_len) {
    if (key->family == 6) write_tcp_v6(f, key, flags, seq, ack, payload, payload_len);
    else write_tcp_v4(f, key, flags, seq, ack, payload, payload_len);
}

static tcp_flow_t *create_tcp_flow(netcap_forward_engine_t *f, const netcap_flow_key_t *key, uint32_t client_isn) {
    if (f->tcp_free_head == NETCAP_NIL_FWD) {
        for (uint32_t i = 0; i < f->tcp_capacity; i++) {
            if (f->tcp_flows[i].occupied) { close_tcp_flow_slot(f, i); break; }
        }
        if (f->tcp_free_head == NETCAP_NIL_FWD) return NULL;
    }

    int is_dest_loopback = (key->family == 4 && key->dst_ip[0] == 127);
    int use_socks5 = (f->socks5_port > 0) && !is_dest_loopback;
    int family = use_socks5 ? ((f->socks5_family == 6) ? AF_INET6 : AF_INET)
                            : ((key->family == 4) ? AF_INET : AF_INET6);
    int sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return NULL;

    fcntl(sock, F_SETFL, O_NONBLOCK);
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (f->protect_cb && f->protect_cb(sock, f->protect_user_data) != 0) {
        close(sock);
        return NULL;
    }

    struct sockaddr_storage dst = {0};
    socklen_t dst_len;
    if (use_socks5) {
        if (f->socks5_family == 6) {
            struct sockaddr_in6 *d = (struct sockaddr_in6 *)&dst;
            d->sin6_family = AF_INET6;
            d->sin6_port = htons(f->socks5_port);
            memcpy(&d->sin6_addr, f->socks5_ip, 16);
            dst_len = sizeof(*d);
        } else {
            struct sockaddr_in *d = (struct sockaddr_in *)&dst;
            d->sin_family = AF_INET;
            d->sin_port = htons(f->socks5_port);
            memcpy(&d->sin_addr, f->socks5_ip, 4);
            dst_len = sizeof(*d);
        }
    } else {
        if (key->family == 4) {
            struct sockaddr_in *d = (struct sockaddr_in *)&dst;
            d->sin_family = AF_INET;
            d->sin_port = htons(key->dst_port);
            memcpy(&d->sin_addr, key->dst_ip, 4);
            dst_len = sizeof(*d);
        } else {
            struct sockaddr_in6 *d = (struct sockaddr_in6 *)&dst;
            d->sin6_family = AF_INET6;
            d->sin6_port = htons(key->dst_port);
            memcpy(&d->sin6_addr, key->dst_ip, 16);
            dst_len = sizeof(*d);
        }
    }

    int rc = connect(sock, (struct sockaddr *)&dst, dst_len);
    if (rc != 0 && errno != EINPROGRESS) {
        close(sock);
        return NULL;
    }

    uint32_t idx = f->tcp_free_head;
    f->tcp_free_head = f->tcp_flows[idx].hash_next;
    tcp_flow_t *s = &f->tcp_flows[idx];
    memset(s, 0, sizeof(*s));
    s->key = *key;
    s->sock = sock;
    s->last_seen = time(NULL);
    s->client_seq = client_isn + 1;
    s->server_seq = 1000000000u + (uint32_t)rand();
    s->occupied = 1;

    if (use_socks5) {
        if (rc == 0) {
            uint8_t greeting[3] = { 0x05, 0x01, 0x00 };
            ssize_t sn = send(sock, greeting, 3, 0);
            s->state = (sn == 3) ? TCP_FLOW_SOCKS_GREETING_ACK : TCP_FLOW_SOCKS_CONNECTING;
        } else {
            s->state = TCP_FLOW_SOCKS_CONNECTING;
        }
    } else {
        s->state = (rc == 0) ? TCP_FLOW_ESTABLISHED : TCP_FLOW_CONNECTING;
    }

    uint32_t bucket = fwd_hash(key) & f->tcp_bucket_mask;
    s->hash_next = f->tcp_buckets[bucket];
    f->tcp_buckets[bucket] = idx;
    f->tcp_count++;

    if (!use_socks5 && s->state == TCP_FLOW_ESTABLISHED) {
        /* Immediate connect: reply SYN-ACK */
        write_tcp(f, key, TCP_FLAG_SYN | TCP_FLAG_ACK, s->server_seq, s->client_seq, NULL, 0);
        s->server_seq += 1;
    }

    return s;
}

int netcap_forward_handle_tcp(netcap_forward_engine_t *f,
                               const netcap_flow_key_t *key,
                               const uint8_t *full_packet, uint32_t packet_len,
                               uint32_t ip_hdr_len, uint32_t tcp_hdr_len,
                               uint8_t tcp_flags, uint32_t seq, uint32_t ack) {
    (void)ack;
    tcp_flow_t *flow = find_tcp_flow(f, key);

    /* 1. Client SYN */
    if (tcp_flags & TCP_FLAG_SYN) {
        if (!flow) {
            flow = create_tcp_flow(f, key, seq);
            return flow ? 0 : -1;
        }
        return 0;
    }

    if (!flow) {
        /* Out-of-order or unknown flow: reply with RST */
        if (!(tcp_flags & TCP_FLAG_RST)) {
            write_tcp(f, key, TCP_FLAG_RST | TCP_FLAG_ACK, 0, seq + 1, NULL, 0);
        }
        return -1;
    }

    flow->last_seen = time(NULL);

    /* 2. Client RST */
    if (tcp_flags & TCP_FLAG_RST) {
        uint32_t bucket = fwd_hash(key) & f->tcp_bucket_mask;
        uint32_t cur = f->tcp_buckets[bucket];
        while (cur != NETCAP_NIL_FWD) {
            if (&f->tcp_flows[cur] == flow) {
                close_tcp_flow_slot(f, cur);
                break;
            }
            cur = f->tcp_flows[cur].hash_next;
        }
        return 0;
    }

    /* 3. Client FIN */
    if (tcp_flags & TCP_FLAG_FIN) {
        flow->client_seq = seq + 1;
        shutdown(flow->sock, SHUT_WR);
        write_tcp(f, key, TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
        flow->state = TCP_FLOW_FIN_WAIT;
        return 0;
    }

    /* 4. Client Payload / Data */
    if (packet_len > ip_hdr_len + tcp_hdr_len) {
        const uint8_t *payload = full_packet + ip_hdr_len + tcp_hdr_len;
        uint32_t payload_len = packet_len - ip_hdr_len - tcp_hdr_len;

        if (flow->state == TCP_FLOW_ESTABLISHED) {
            int32_t diff = (int32_t)(seq - flow->client_seq);
            if (diff <= 0) {
                /* Packet starts at or before expected client_seq */
                int32_t end_diff = (int32_t)((seq + payload_len) - flow->client_seq);
                if (end_diff <= 0) {
                    /* Retransmission guard: all bytes in this packet were already sent to socket.
                     * Re-ACK expected sequence to quench client retransmissions. */
                    write_tcp(f, key, TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                    return 0;
                }
                /* Partial overlap: skip already forwarded bytes */
                uint32_t skip = flow->client_seq - seq;
                payload += skip;
                payload_len -= skip;
            }

            size_t total_sent = 0;
            while (total_sent < payload_len) {
                ssize_t sent = send(flow->sock, payload + total_sent, payload_len - total_sent, 0);
                if (sent > 0) {
                    total_sent += (size_t)sent;
                } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    break;
                } else {
                    break;
                }
            }
            if (total_sent > 0) {
                flow->client_seq += (uint32_t)total_sent;
                /* Send ACK back to client */
                write_tcp(f, key, TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
            }
        }
    }

    return 0;
}

void netcap_forward_poll_replies(netcap_forward_engine_t *f) {
    /* 1. Poll UDP replies */
    uint8_t udp_buf[MAX_UDP_REPLY];
    for (uint32_t i = 0; i < f->udp_capacity; i++) {
        if (!f->udp_flows[i].occupied) continue;
        udp_flow_t *s = &f->udp_flows[i];
        for (;;) {
            ssize_t n = recv(s->sock, udp_buf, sizeof(udp_buf), 0);
            if (n <= 0) break;
            s->last_seen = time(NULL);
            if (s->key.family == 4) write_reply_v4_udp(f, s, udp_buf, (uint32_t)n);
            else if (s->key.family == 6) write_reply_v6_udp(f, s, udp_buf, (uint32_t)n);
        }
    }

    /* 1b. Poll ICMP echo replies */
    uint8_t icmp_buf[MAX_ICMP_REPLY];
    for (uint32_t i = 0; i < MAX_ICMP_FLOWS; i++) {
        icmp_flow_t *s = &f->icmp_flows[i];
        if (!s->occupied) continue;
        for (;;) {
            ssize_t n = recv(s->sock, icmp_buf, sizeof(icmp_buf), 0);
            if (n <= 0) break;
            s->last_seen = time(NULL);
            if (icmp_buf[0] == 0 /* echo reply */) write_reply_v4_icmp(f, s, icmp_buf, (uint32_t)n);
        }
    }

    /* 2. Poll TCP sockets */
    struct pollfd pfds[256];
    uint32_t flow_indices[256];
    uint32_t npoll = 0;

    for (uint32_t i = 0; i < f->tcp_capacity && npoll < 256; i++) {
        if (!f->tcp_flows[i].occupied) continue;
        tcp_flow_t *s = &f->tcp_flows[i];
        pfds[npoll].fd = s->sock;
        pfds[npoll].revents = 0;
        flow_indices[npoll] = i;

        if (s->state == TCP_FLOW_CONNECTING || s->state == TCP_FLOW_SOCKS_CONNECTING) {
            pfds[npoll].events = POLLOUT | POLLERR | POLLHUP;
        } else if (s->state == TCP_FLOW_SOCKS_GREETING_ACK || s->state == TCP_FLOW_SOCKS_CONNECT_ACK) {
            pfds[npoll].events = POLLIN | POLLERR | POLLHUP;
        } else if (s->state == TCP_FLOW_ESTABLISHED) {
            pfds[npoll].events = POLLIN | POLLERR | POLLHUP;
        } else {
            pfds[npoll].events = POLLIN;
        }
        npoll++;
    }

    if (npoll == 0) return;

    int rc = poll(pfds, npoll, 0);
    if (rc <= 0) return;

    uint8_t tcp_buf[MAX_TCP_REPLY];

    for (uint32_t k = 0; k < npoll; k++) {
        if (pfds[k].revents == 0) continue;
        uint32_t idx = flow_indices[k];
        if (!f->tcp_flows[idx].occupied) continue;
        tcp_flow_t *flow = &f->tcp_flows[idx];

        /* SOCKS5 connecting socket */
        if (flow->state == TCP_FLOW_SOCKS_CONNECTING) {
            if (pfds[k].revents & POLLOUT) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(flow->sock, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) {
                    uint8_t greeting[3] = { 0x05, 0x01, 0x00 };
                    ssize_t sn = send(flow->sock, greeting, 3, 0);
                    if (sn == 3) {
                        flow->state = TCP_FLOW_SOCKS_GREETING_ACK;
                        flow->last_seen = time(NULL);
                    } else {
                        write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                        close_tcp_flow_slot(f, idx);
                    }
                } else {
                    write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                    close_tcp_flow_slot(f, idx);
                }
            } else if (pfds[k].revents & (POLLERR | POLLHUP)) {
                write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                close_tcp_flow_slot(f, idx);
            }
            continue;
        }

        /* SOCKS5 waiting for greeting response */
        if (flow->state == TCP_FLOW_SOCKS_GREETING_ACK) {
            if (pfds[k].revents & POLLIN) {
                uint8_t resp[2];
                ssize_t n = recv(flow->sock, resp, 2, 0);
                if (n == 2 && resp[0] == 0x05 && resp[1] == 0x00) {
                    if (flow->key.family == 4) {
                        uint8_t req[10];
                        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01;
                        memcpy(req + 4, flow->key.dst_ip, 4);
                        uint16_t dp = htons(flow->key.dst_port);
                        memcpy(req + 8, &dp, 2);
                        send(flow->sock, req, 10, 0);
                    } else {
                        uint8_t req[22];
                        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x04;
                        memcpy(req + 4, flow->key.dst_ip, 16);
                        uint16_t dp = htons(flow->key.dst_port);
                        memcpy(req + 20, &dp, 2);
                        send(flow->sock, req, 22, 0);
                    }
                    flow->state = TCP_FLOW_SOCKS_CONNECT_ACK;
                    flow->last_seen = time(NULL);
                } else {
                    write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                    close_tcp_flow_slot(f, idx);
                }
            } else if (pfds[k].revents & (POLLERR | POLLHUP)) {
                write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                close_tcp_flow_slot(f, idx);
            }
            continue;
        }

        /* SOCKS5 waiting for connect response */
        if (flow->state == TCP_FLOW_SOCKS_CONNECT_ACK) {
            if (pfds[k].revents & POLLIN) {
                uint8_t resp[64];
                ssize_t n = recv(flow->sock, resp, sizeof(resp), 0);
                if (n >= 4 && resp[0] == 0x05 && resp[1] == 0x00) {
                    flow->state = TCP_FLOW_ESTABLISHED;
                    flow->last_seen = time(NULL);
                    write_tcp(f, &flow->key, TCP_FLAG_SYN | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                    flow->server_seq += 1;
                } else {
                    write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                    close_tcp_flow_slot(f, idx);
                }
            } else if (pfds[k].revents & (POLLERR | POLLHUP)) {
                write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                close_tcp_flow_slot(f, idx);
            }
            continue;
        }

        /* Connecting socket */
        if (flow->state == TCP_FLOW_CONNECTING) {
            if (pfds[k].revents & POLLOUT) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(flow->sock, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) {
                    /* Successfully connected to destination server! */
                    flow->state = TCP_FLOW_ESTABLISHED;
                    flow->last_seen = time(NULL);
                    /* Send synthetic SYN-ACK to client */
                    write_tcp(f, &flow->key, TCP_FLAG_SYN | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                    flow->server_seq += 1;
                } else {
                    /* Connection failed: send RST to client */
                    write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                    close_tcp_flow_slot(f, idx);
                }
            } else if (pfds[k].revents & (POLLERR | POLLHUP)) {
                write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                close_tcp_flow_slot(f, idx);
            }
            continue;
        }

        /* Established socket */
        if (flow->state == TCP_FLOW_ESTABLISHED || flow->state == TCP_FLOW_FIN_WAIT) {
            if (pfds[k].revents & POLLIN) {
                for (int iter = 0; iter < 16; iter++) {
                    ssize_t n = recv(flow->sock, tcp_buf, sizeof(tcp_buf), 0);
                    if (n > 0) {
                        flow->last_seen = time(NULL);
                        /* Deliver server data to client */
                        write_tcp(f, &flow->key, TCP_FLAG_ACK | TCP_FLAG_PSH, flow->server_seq, flow->client_seq, tcp_buf, (uint32_t)n);
                        flow->server_seq += (uint32_t)n;
                    } else if (n == 0) {
                        /* Server sent FIN */
                        write_tcp(f, &flow->key, TCP_FLAG_FIN | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                        flow->server_seq += 1;
                        close_tcp_flow_slot(f, idx);
                        break;
                    } else {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                            close_tcp_flow_slot(f, idx);
                        }
                        break;
                    }
                }
            } else if (pfds[k].revents & (POLLERR | POLLHUP)) {
                write_tcp(f, &flow->key, TCP_FLAG_RST | TCP_FLAG_ACK, flow->server_seq, flow->client_seq, NULL, 0);
                close_tcp_flow_slot(f, idx);
            }
        }
    }
}

void netcap_forward_sweep_idle(netcap_forward_engine_t *f, uint32_t idle_secs) {
    time_t now = time(NULL);
    /* Sweep UDP */
    for (uint32_t i = 0; i < f->udp_capacity; i++) {
        if (f->udp_flows[i].occupied && (uint32_t)(now - f->udp_flows[i].last_seen) >= idle_secs) {
            close_udp_flow_slot(f, i);
        }
    }
    /* Sweep TCP */
    for (uint32_t i = 0; i < f->tcp_capacity; i++) {
        if (f->tcp_flows[i].occupied) {
            uint32_t timeout = idle_secs;
            if (f->tcp_flows[i].state != TCP_FLOW_ESTABLISHED && f->tcp_flows[i].state != TCP_FLOW_FIN_WAIT) {
                timeout = 10; /* 10 seconds timeout for connecting / SOCKS handshake */
            }
            if ((uint32_t)(now - f->tcp_flows[i].last_seen) >= timeout) {
                close_tcp_flow_slot(f, i);
            }
        }
    }
    /* Sweep ICMP (echo flows are short-lived; cap at 30s) */
    uint32_t icmp_idle = idle_secs < 30 ? idle_secs : 30;
    for (uint32_t i = 0; i < MAX_ICMP_FLOWS; i++) {
        if (f->icmp_flows[i].occupied && (uint32_t)(now - f->icmp_flows[i].last_seen) >= icmp_idle) {
            close_icmp_flow(&f->icmp_flows[i]);
        }
    }
}
