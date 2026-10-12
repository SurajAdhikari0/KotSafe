#define _POSIX_C_SOURCE 200809L
#include "proxy_relay.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_PROXY_RULES 64

typedef struct {
    uint8_t proto;
    uint16_t orig_port;
    uint16_t redirect_port;
    uint8_t redirect_ip[16];
    uint8_t family;
    bool active;
} proxy_rule_t;

struct netcap_proxy_relay {
    proxy_rule_t rules[MAX_PROXY_RULES];
    uint32_t num_rules;

    int32_t *exempt_uids;
    uint32_t exempt_count;
};

netcap_proxy_relay_t *netcap_proxy_relay_create(void) {
    return calloc(1, sizeof(netcap_proxy_relay_t));
}

void netcap_proxy_relay_destroy(netcap_proxy_relay_t *pr) {
    if (!pr) return;
    free(pr->exempt_uids);
    free(pr);
}

int netcap_proxy_relay_add_rule(netcap_proxy_relay_t *pr, uint8_t proto,
                                uint16_t orig_port, uint16_t redirect_port,
                                const char *redirect_ip) {
    if (!pr || !redirect_ip) return -1;

    struct in_addr a4;
    struct in6_addr a6;
    uint8_t ip_buf[16] = {0};
    uint8_t family = 0;

    if (inet_pton(AF_INET, redirect_ip, &a4) == 1) {
        family = 4;
        memcpy(ip_buf, &a4.s_addr, 4);
    } else if (inet_pton(AF_INET6, redirect_ip, &a6) == 1) {
        family = 6;
        memcpy(ip_buf, &a6.s6_addr, 16);
    } else {
        return -1;
    }

    /* Update existing rule if present */
    for (uint32_t i = 0; i < MAX_PROXY_RULES; i++) {
        if (pr->rules[i].active && pr->rules[i].proto == proto && pr->rules[i].orig_port == orig_port) {
            pr->rules[i].redirect_port = redirect_port;
            memcpy(pr->rules[i].redirect_ip, ip_buf, 16);
            pr->rules[i].family = family;
            return 0;
        }
    }

    /* Find free slot */
    for (uint32_t i = 0; i < MAX_PROXY_RULES; i++) {
        if (!pr->rules[i].active) {
            pr->rules[i].proto = proto;
            pr->rules[i].orig_port = orig_port;
            pr->rules[i].redirect_port = redirect_port;
            memcpy(pr->rules[i].redirect_ip, ip_buf, 16);
            pr->rules[i].family = family;
            pr->rules[i].active = true;
            pr->num_rules++;
            return 0;
        }
    }

    return -1; /* Table full */
}

void netcap_proxy_relay_remove_rule(netcap_proxy_relay_t *pr, uint8_t proto, uint16_t orig_port) {
    if (!pr) return;
    for (uint32_t i = 0; i < MAX_PROXY_RULES; i++) {
        if (pr->rules[i].active && pr->rules[i].proto == proto && pr->rules[i].orig_port == orig_port) {
            pr->rules[i].active = false;
            pr->num_rules--;
            break;
        }
    }
}

void netcap_proxy_relay_clear_rules(netcap_proxy_relay_t *pr) {
    if (!pr) return;
    memset(pr->rules, 0, sizeof(pr->rules));
    pr->num_rules = 0;
}

static int uid_cmp(const void *a, const void *b) {
    int32_t ia = *(const int32_t *)a;
    int32_t ib = *(const int32_t *)b;
    return (ia > ib) - (ia < ib);
}

void netcap_proxy_relay_set_exempt_uids(netcap_proxy_relay_t *pr, const int32_t *uids, uint32_t count) {
    if (!pr) return;
    free(pr->exempt_uids);
    pr->exempt_uids = NULL;
    pr->exempt_count = 0;

    if (uids && count > 0) {
        pr->exempt_uids = malloc(count * sizeof(int32_t));
        if (pr->exempt_uids) {
            memcpy(pr->exempt_uids, uids, count * sizeof(int32_t));
            pr->exempt_count = count;
            qsort(pr->exempt_uids, count, sizeof(int32_t), uid_cmp);
        }
    }
}

bool netcap_proxy_relay_match(const netcap_proxy_relay_t *pr, int32_t uid,
                              uint8_t proto, uint16_t orig_port,
                              uint8_t out_dst_ip[16], uint16_t *out_dst_port,
                              uint8_t *out_family) {
    if (!pr || pr->num_rules == 0) return false;

    /* Check if UID is exempt */
    if (uid >= 0 && pr->exempt_count > 0) {
        if (bsearch(&uid, pr->exempt_uids, pr->exempt_count, sizeof(int32_t), uid_cmp) != NULL) {
            return false; /* Exempt! */
        }
    }

    for (uint32_t i = 0; i < MAX_PROXY_RULES; i++) {
        if (pr->rules[i].active && pr->rules[i].proto == proto && pr->rules[i].orig_port == orig_port) {
            if (out_dst_ip) memcpy(out_dst_ip, pr->rules[i].redirect_ip, 16);
            if (out_dst_port) *out_dst_port = pr->rules[i].redirect_port;
            if (out_family) *out_family = pr->rules[i].family;
            return true;
        }
    }

    return false;
}

static uint16_t compute_ip_csum(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t compute_tcp_csum_v4(const uint8_t src_ip[4], const uint8_t dst_ip[4],
                                    const uint8_t *tcp_seg, uint16_t tcp_len) {
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)src_ip;
    sum += p[0]; sum += p[1];
    p = (const uint16_t *)dst_ip;
    sum += p[0]; sum += p[1];
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    p = (const uint16_t *)tcp_seg;
    uint32_t count = tcp_len;
    while (count > 1) { sum += *p++; count -= 2; }
    if (count > 0) {
        uint8_t last[2] = { *(const uint8_t *)p, 0 };
        sum += *(const uint16_t *)last;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

bool netcap_proxy_relay_rewrite_packet(const netcap_proxy_relay_t *pr, int32_t uid,
                                       uint8_t *pkt, uint32_t len, uint32_t ip_hdr_len,
                                       uint8_t proto, uint8_t family,
                                       uint8_t out_redir_ip[16], uint16_t *out_redir_port) {
    if (!pr || !pkt || len < ip_hdr_len + 8) return false;

    uint16_t orig_port = ntohs(*(const uint16_t *)(pkt + ip_hdr_len + 2));
    uint8_t target_ip[16];
    uint16_t target_port = 0;
    uint8_t target_family = 0;

    if (!netcap_proxy_relay_match(pr, uid, proto, orig_port, target_ip, &target_port, &target_family)) {
        return false;
    }

    if (family == 4 && target_family == 4) {
        /* Rewrite destination IP (bytes 16..19) */
        memcpy(pkt + 16, target_ip, 4);

        /* Rewrite destination Port (offset ip_hdr_len + 2) */
        uint16_t np = htons(target_port);
        memcpy(pkt + ip_hdr_len + 2, &np, 2);

        /* Recompute IPv4 Header Checksum */
        pkt[10] = 0;
        pkt[11] = 0;
        uint16_t ipcsum = compute_ip_csum(pkt, ip_hdr_len);
        memcpy(pkt + 10, &ipcsum, 2);

        /* Recompute L4 checksum */
        if (proto == 6 && len >= ip_hdr_len + 20) { /* TCP */
            pkt[ip_hdr_len + 16] = 0;
            pkt[ip_hdr_len + 17] = 0;
            uint16_t tcpcsum = compute_tcp_csum_v4(pkt + 12, pkt + 16, pkt + ip_hdr_len, (uint16_t)(len - ip_hdr_len));
            memcpy(pkt + ip_hdr_len + 16, &tcpcsum, 2);
        } else if (proto == 17) { /* UDP */
            pkt[ip_hdr_len + 6] = 0;
            pkt[ip_hdr_len + 7] = 0;
        }

        if (out_redir_ip) memcpy(out_redir_ip, target_ip, 16);
        if (out_redir_port) *out_redir_port = target_port;
        return true;
    }

    return false;
}
