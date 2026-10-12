#define _POSIX_C_SOURCE 200809L
#include "dns_policy.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct netcap_dns_policy {
    bool block_dot;

    bool has_custom_dns;
    uint8_t custom_dns_ip[16];
    uint8_t custom_dns_family;

    int32_t *lan_blocked_uids;
    uint32_t lan_blocked_count;
};

netcap_dns_policy_t *netcap_dns_policy_create(void) {
    netcap_dns_policy_t *pol = calloc(1, sizeof(netcap_dns_policy_t));
    if (pol) {
        pol->has_custom_dns = true;
        pol->custom_dns_family = 4;
        pol->custom_dns_ip[0] = 1;
        pol->custom_dns_ip[1] = 1;
        pol->custom_dns_ip[2] = 1;
        pol->custom_dns_ip[3] = 1;
    }
    return pol;
}

void netcap_dns_policy_destroy(netcap_dns_policy_t *pol) {
    if (!pol) return;
    free(pol->lan_blocked_uids);
    free(pol);
}

void netcap_dns_policy_set_block_dot(netcap_dns_policy_t *pol, bool block) {
    if (pol) pol->block_dot = block;
}

bool netcap_dns_policy_is_dot_blocked(const netcap_dns_policy_t *pol) {
    return pol ? pol->block_dot : false;
}

int netcap_dns_policy_set_custom_dns(netcap_dns_policy_t *pol, const char *dns_ip) {
    if (!pol) return -1;
    if (!dns_ip || dns_ip[0] == '\0') {
        pol->has_custom_dns = true;
        pol->custom_dns_family = 4;
        memset(pol->custom_dns_ip, 0, sizeof(pol->custom_dns_ip));
        pol->custom_dns_ip[0] = 1;
        pol->custom_dns_ip[1] = 1;
        pol->custom_dns_ip[2] = 1;
        pol->custom_dns_ip[3] = 1;
        return 0;
    }

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, dns_ip, &a4) == 1) {
        pol->has_custom_dns = true;
        pol->custom_dns_family = 4;
        memset(pol->custom_dns_ip, 0, 16);
        memcpy(pol->custom_dns_ip, &a4.s_addr, 4);
        return 0;
    } else if (inet_pton(AF_INET6, dns_ip, &a6) == 1) {
        pol->has_custom_dns = true;
        pol->custom_dns_family = 6;
        memcpy(pol->custom_dns_ip, &a6.s6_addr, 16);
        return 0;
    }
    return -1;
}

bool netcap_dns_policy_get_custom_dns(const netcap_dns_policy_t *pol, uint8_t out_ip[16], uint8_t *out_family) {
    if (!pol || !pol->has_custom_dns) return false;
    if (out_ip) memcpy(out_ip, pol->custom_dns_ip, 16);
    if (out_family) *out_family = pol->custom_dns_family;
    return true;
}

static int uid_compare(const void *a, const void *b) {
    int32_t ia = *(const int32_t *)a;
    int32_t ib = *(const int32_t *)b;
    return (ia > ib) - (ia < ib);
}

void netcap_dns_policy_set_lan_blocked_uids(netcap_dns_policy_t *pol, const int32_t *uids, uint32_t count) {
    if (!pol) return;
    free(pol->lan_blocked_uids);
    pol->lan_blocked_uids = NULL;
    pol->lan_blocked_count = 0;

    if (uids && count > 0) {
        pol->lan_blocked_uids = malloc(count * sizeof(int32_t));
        if (pol->lan_blocked_uids) {
            memcpy(pol->lan_blocked_uids, uids, count * sizeof(int32_t));
            pol->lan_blocked_count = count;
            qsort(pol->lan_blocked_uids, count, sizeof(int32_t), uid_compare);
        }
    }
}

static bool is_lan_ip(const uint8_t *dst_ip, uint8_t family) {
    if (!dst_ip) return false;
    if (family == 4) {
        if (dst_ip[0] == 10) return true;                           /* 10.0.0.0/8 */
        if (dst_ip[0] == 172 && (dst_ip[1] >= 16 && dst_ip[1] <= 31)) return true; /* 172.16.0.0/12 */
        if (dst_ip[0] == 192 && dst_ip[1] == 168) return true;      /* 192.168.0.0/16 */
        if (dst_ip[0] == 169 && dst_ip[1] == 254) return true;      /* 169.254.0.0/16 */
        if (dst_ip[0] == 127) return true;                          /* 127.0.0.0/8 */
        return false;
    } else if (family == 6) {
        /* fe80::/10 link local */
        if (dst_ip[0] == 0xFE && (dst_ip[1] & 0xC0) == 0x80) return true;
        /* fc00::/7 unique local */
        if ((dst_ip[0] & 0xFE) == 0xFC) return true;
        /* ::1 */
        static const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(dst_ip, loopback, 16) == 0) return true;
        return false;
    }
    return false;
}

bool netcap_dns_policy_is_lan_blocked(const netcap_dns_policy_t *pol, int32_t uid, const uint8_t *dst_ip, uint8_t family) {
    if (!pol || uid < 0 || pol->lan_blocked_count == 0) return false;
    if (!is_lan_ip(dst_ip, family)) return false;

    /* Binary search for UID */
    const int32_t *res = bsearch(&uid, pol->lan_blocked_uids, pol->lan_blocked_count, sizeof(int32_t), uid_compare);
    return (res != NULL);
}

static uint16_t compute_checksum(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

bool netcap_dns_policy_rewrite_dns_packet(const netcap_dns_policy_t *pol, uint8_t *pkt, uint32_t len, uint32_t ip_hdr_len, uint8_t family) {
    if (!pol || !pol->has_custom_dns || !pkt || len < ip_hdr_len + 8) return false;

    if (family == 4 && pol->custom_dns_family == 4) {
        /* Rewrite IPv4 destination IP (bytes 16..19) */
        memcpy(pkt + 16, pol->custom_dns_ip, 4);

        /* Recompute IPv4 Header Checksum */
        pkt[10] = 0;
        pkt[11] = 0;
        uint16_t csum = compute_checksum(pkt, ip_hdr_len);
        memcpy(pkt + 10, &csum, 2);

        /* Clear UDP checksum (optional in IPv4) */
        pkt[ip_hdr_len + 6] = 0;
        pkt[ip_hdr_len + 7] = 0;
        return true;
    } else if (family == 6 && pol->custom_dns_family == 6) {
        /* Rewrite IPv6 destination IP (bytes 24..39) */
        memcpy(pkt + 24, pol->custom_dns_ip, 16);
        return true;
    }
    return false;
}
