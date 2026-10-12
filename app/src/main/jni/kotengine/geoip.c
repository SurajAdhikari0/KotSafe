#define _POSIX_C_SOURCE 200809L
#include "geoip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct {
    uint32_t start_ip;
    uint32_t end_ip;
    char cc[3];
} geoip_range_v4_t;

/* Built-in ranges for popular DNS, CDNs, and major RIR global subnets */
static const geoip_range_v4_t builtin_v4[] = {
    /* Cloudflare */
    { 0x01010101, 0x01010101, "US" }, /* 1.1.1.1 */
    { 0x01000001, 0x01000001, "US" }, /* 1.0.0.1 */
    { 0x68100000, 0x681fffff, "US" }, /* 104.16.0.0/12 */

    /* Google */
    { 0x08080808, 0x08080808, "US" }, /* 8.8.8.8 */
    { 0x08080404, 0x08080404, "US" }, /* 8.8.4.4 */
    { 0x8efa0000, 0x8efaffff, "US" }, /* 142.250.0.0/16 */
    { 0xacd90000, 0xacd9ffff, "US" }, /* 172.217.0.0/16 */

    /* Quad9 & OpenDNS */
    { 0x09090909, 0x09090909, "CH" }, /* 9.9.9.9 */
    { 0xd043dede, 0xd043dede, "US" }, /* 208.67.222.222 */

    /* Major AWS US & Global */
    { 0x34c00000, 0x34dfffff, "US" }, /* 52.192.0.0/11 - AWS */
    { 0x36e00000, 0x36ffffff, "US" }, /* 54.224.0.0/11 - AWS */

    /* European ranges (RIPE) */
    { 0x50580000, 0x505fffff, "DE" }, /* 80.88.0.0/13 */
    { 0x55000000, 0x55ffffff, "FR" }, /* 85.0.0.0/8 */
    { 0x97000000, 0x97ffffff, "GB" }, /* 151.0.0.0/8 */
    { 0x5bb00000, 0x5bbfffff, "NL" }, /* 91.176.0.0/12 */

    /* Asian ranges (APNIC) */
    { 0x67c00000, 0x67ffffff, "IN" }, /* 103.192.0.0/10 */
    { 0x6df00000, 0x6dffffff, "IN" }, /* 109.240.0.0/12 */
    { 0x3df00000, 0x3dffffff, "IN" }, /* 61.240.0.0/12 */
    { 0x85000000, 0x85ffffff, "JP" }, /* 133.0.0.0/8 */
    { 0x76c00000, 0x76ffffff, "SG" }, /* 118.192.0.0/10 */
    { 0x01800000, 0x01ffffff, "AU" }  /* 1.128.0.0/9 */
};

#define NUM_BUILTIN_V4 (sizeof(builtin_v4) / sizeof(builtin_v4[0]))

/* Dynamic loaded database table */
static geoip_range_v4_t *s_dyn_table = NULL;
static size_t s_dyn_count = 0;
static size_t s_dyn_capacity = 0;

static inline bool is_private_v4(uint32_t ip_host) {
    if ((ip_host >> 24) == 127) return true;         /* 127.0.0.0/8 */
    if ((ip_host >> 24) == 10)  return true;         /* 10.0.0.0/8 */
    if ((ip_host >> 20) == 0xAC1) return true;       /* 172.16.0.0/12 */
    if ((ip_host >> 16) == 0xC0A8) return true;      /* 192.168.0.0/16 */
    if ((ip_host >> 16) == 0xA9FE) return true;      /* 169.254.0.0/16 */
    return false;
}

static inline bool is_private_v6(const uint8_t *ip) {
    /* ::1 */
    static const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(ip, loopback, 16) == 0) return true;
    /* fe80::/10 link local */
    if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return true;
    /* fc00::/7 unique local */
    if ((ip[0] & 0xFE) == 0xFC) return true;
    return false;
}

static const char *lookup_v4(uint32_t ip_host) {
    if (is_private_v4(ip_host)) return "LO";

    /* Check dynamic table if loaded */
    if (s_dyn_table && s_dyn_count > 0) {
        size_t low = 0, high = s_dyn_count;
        while (low < high) {
            size_t mid = low + (high - low) / 2;
            if (ip_host < s_dyn_table[mid].start_ip) {
                high = mid;
            } else if (ip_host > s_dyn_table[mid].end_ip) {
                low = mid + 1;
            } else {
                return s_dyn_table[mid].cc;
            }
        }
    }

    /* Check built-in table */
    for (size_t i = 0; i < NUM_BUILTIN_V4; i++) {
        if (ip_host >= builtin_v4[i].start_ip && ip_host <= builtin_v4[i].end_ip) {
            return builtin_v4[i].cc;
        }
    }

    return "ZZ";
}

const char *netcap_geoip_lookup(const uint8_t *ip, uint8_t family) {
    if (!ip) return "";
    if (family == 4) {
        uint32_t ip_host = ((uint32_t)ip[0] << 24) |
                           ((uint32_t)ip[1] << 16) |
                           ((uint32_t)ip[2] << 8)  |
                           (uint32_t)ip[3];
        return lookup_v4(ip_host);
    } else if (family == 6) {
        if (is_private_v6(ip)) return "LO";
        /* Check 6to4 / ::ffff:a.b.c.d mapped IPv4 */
        static const uint8_t v4_mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
        if (memcmp(ip, v4_mapped_prefix, 12) == 0) {
            uint32_t ip_host = ((uint32_t)ip[12] << 24) |
                               ((uint32_t)ip[13] << 16) |
                               ((uint32_t)ip[14] << 8)  |
                               (uint32_t)ip[15];
            return lookup_v4(ip_host);
        }
        return "ZZ";
    }
    return "";
}

int netcap_geoip_load_file(const char *path) {
    if (!path) return -1;
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[128];
    size_t loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        char s_ip[32], e_ip[32], cc[8];
        if (sscanf(line, "%31[^,],%31[^,],%7s", s_ip, e_ip, cc) != 3) continue;

        struct in_addr a1, a2;
        if (inet_pton(AF_INET, s_ip, &a1) != 1 || inet_pton(AF_INET, e_ip, &a2) != 1) continue;

        if (s_dyn_count >= s_dyn_capacity) {
            size_t new_cap = (s_dyn_capacity == 0) ? 256 : s_dyn_capacity * 2;
            geoip_range_v4_t *new_tbl = realloc(s_dyn_table, new_cap * sizeof(geoip_range_v4_t));
            if (!new_tbl) break;
            s_dyn_table = new_tbl;
            s_dyn_capacity = new_cap;
        }

        s_dyn_table[s_dyn_count].start_ip = ntohl(a1.s_addr);
        s_dyn_table[s_dyn_count].end_ip = ntohl(a2.s_addr);
        strncpy(s_dyn_table[s_dyn_count].cc, cc, 2);
        s_dyn_table[s_dyn_count].cc[2] = '\0';
        s_dyn_count++;
        loaded++;
    }

    fclose(fp);
    return (int)loaded;
}
