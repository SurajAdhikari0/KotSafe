#define _POSIX_C_SOURCE 200809L
#include "dns_cache.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stdio.h>

#define DEFAULT_CAPACITY 2048
#define MAX_DOMAIN_LEN 256
#define MIN_TTL_SECS 30
#define MAX_TTL_SECS 86400

typedef struct dns_entry {
    uint8_t ip[16];
    uint8_t family; /* 4 or 6 */
    char domain[MAX_DOMAIN_LEN];
    time_t expires_at;
    time_t last_accessed;
    struct dns_entry *next;
} dns_entry_t;

struct netcap_dns_cache {
    uint32_t capacity;
    uint32_t count;
    uint32_t nbuckets;
    dns_entry_t **buckets;
    pthread_mutex_t lock;
};

static inline uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t hash_ip(const uint8_t *ip, uint8_t family) {
    uint32_t h = 2166136261u;
    size_t len = (family == 4) ? 4 : 16;
    for (size_t i = 0; i < len; i++) {
        h ^= ip[i];
        h *= 16777619u;
    }
    h ^= family;
    h *= 16777619u;
    return h;
}

netcap_dns_cache_t *netcap_dns_cache_create(uint32_t capacity) {
    if (capacity == 0) capacity = DEFAULT_CAPACITY;

    netcap_dns_cache_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->capacity = capacity;
    /* nbuckets as power of 2 roughly 1.5x capacity */
    c->nbuckets = 1;
    while (c->nbuckets < (capacity + capacity / 2)) {
        c->nbuckets <<= 1;
    }

    c->buckets = calloc(c->nbuckets, sizeof(dns_entry_t *));
    if (!c->buckets) {
        free(c);
        return NULL;
    }

    pthread_mutex_init(&c->lock, NULL);
    return c;
}

void netcap_dns_cache_destroy(netcap_dns_cache_t *c) {
    if (!c) return;
    pthread_mutex_lock(&c->lock);
    for (uint32_t i = 0; i < c->nbuckets; i++) {
        dns_entry_t *curr = c->buckets[i];
        while (curr) {
            dns_entry_t *next = curr->next;
            free(curr);
            curr = next;
        }
    }
    free(c->buckets);
    pthread_mutex_unlock(&c->lock);
    pthread_mutex_destroy(&c->lock);
    free(c);
}

void netcap_dns_cache_clear(netcap_dns_cache_t *c) {
    if (!c) return;
    pthread_mutex_lock(&c->lock);
    for (uint32_t i = 0; i < c->nbuckets; i++) {
        dns_entry_t *curr = c->buckets[i];
        while (curr) {
            dns_entry_t *next = curr->next;
            free(curr);
            curr = next;
        }
        c->buckets[i] = NULL;
    }
    c->count = 0;
    pthread_mutex_unlock(&c->lock);
}

bool netcap_dns_cache_lookup(netcap_dns_cache_t *c, const uint8_t *ip, uint8_t family,
                             char *out_domain, size_t max_len) {
    if (!c || !ip || !out_domain || max_len == 0) return false;

    time_t now = time(NULL);
    uint32_t b = hash_ip(ip, family) & (c->nbuckets - 1);
    size_t ip_len = (family == 4) ? 4 : 16;
    bool found = false;

    pthread_mutex_lock(&c->lock);
    dns_entry_t *curr = c->buckets[b];
    dns_entry_t *prev = NULL;

    while (curr) {
        if (curr->family == family && memcmp(curr->ip, ip, ip_len) == 0) {
            if (curr->expires_at < now) {
                /* Expired entry: evict */
                if (prev) prev->next = curr->next;
                else c->buckets[b] = curr->next;
                free(curr);
                c->count--;
                break;
            }

            curr->last_accessed = now;
            strncpy(out_domain, curr->domain, max_len - 1);
            out_domain[max_len - 1] = '\0';
            found = true;
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&c->lock);
    return found;
}

static void evict_oldest_locked(netcap_dns_cache_t *c) {
    time_t now = time(NULL);
    dns_entry_t *oldest = NULL;
    dns_entry_t **oldest_prev_link = NULL;
    time_t oldest_time = now + 864000;

    for (uint32_t i = 0; i < c->nbuckets; i++) {
        dns_entry_t **link = &c->buckets[i];
        while (*link) {
            dns_entry_t *entry = *link;
            /* If already expired, drop immediately */
            if (entry->expires_at < now) {
                *link = entry->next;
                free(entry);
                c->count--;
                return;
            }
            if (entry->last_accessed < oldest_time) {
                oldest_time = entry->last_accessed;
                oldest = entry;
                oldest_prev_link = link;
            }
            link = &entry->next;
        }
    }

    if (oldest && oldest_prev_link) {
        *oldest_prev_link = oldest->next;
        free(oldest);
        c->count--;
    }
}

void netcap_dns_cache_insert(netcap_dns_cache_t *c, const uint8_t *ip, uint8_t family,
                             const char *domain, uint32_t ttl_secs) {
    if (!c || !ip || !domain || domain[0] == '\0') return;

    if (ttl_secs < MIN_TTL_SECS) ttl_secs = MIN_TTL_SECS;
    if (ttl_secs > MAX_TTL_SECS) ttl_secs = MAX_TTL_SECS;

    time_t now = time(NULL);
    uint32_t b = hash_ip(ip, family) & (c->nbuckets - 1);
    size_t ip_len = (family == 4) ? 4 : 16;

    pthread_mutex_lock(&c->lock);

    /* Check if already present to update */
    dns_entry_t *curr = c->buckets[b];
    while (curr) {
        if (curr->family == family && memcmp(curr->ip, ip, ip_len) == 0) {
            strncpy(curr->domain, domain, sizeof(curr->domain) - 1);
            curr->domain[sizeof(curr->domain) - 1] = '\0';
            curr->expires_at = now + ttl_secs;
            curr->last_accessed = now;
            pthread_mutex_unlock(&c->lock);
            return;
        }
        curr = curr->next;
    }

    /* Capacity check */
    if (c->count >= c->capacity) {
        evict_oldest_locked(c);
    }

    dns_entry_t *entry = malloc(sizeof(*entry));
    if (entry) {
        memset(entry, 0, sizeof(*entry));
        memcpy(entry->ip, ip, ip_len);
        entry->family = family;
        strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
        entry->domain[sizeof(entry->domain) - 1] = '\0';
        entry->expires_at = now + ttl_secs;
        entry->last_accessed = now;

        entry->next = c->buckets[b];
        c->buckets[b] = entry;
        c->count++;
    }

    pthread_mutex_unlock(&c->lock);
}

uint32_t netcap_dns_cache_size(netcap_dns_cache_t *c) {
    if (!c) return 0;
    pthread_mutex_lock(&c->lock);
    uint32_t count = c->count;
    pthread_mutex_unlock(&c->lock);
    return count;
}

/* Helper to parse RFC 1035 wire name with compression jump protection */
static bool parse_wire_name(const uint8_t *packet, size_t packet_len, size_t *inout_offset,
                            char *out_name, size_t max_name_len) {
    size_t offset = *inout_offset;
    size_t out_len = 0;
    int jumps = 0;
    size_t orig_offset = 0;

    while (offset < packet_len) {
        uint8_t len = packet[offset++];

        if (len == 0) {
            /* Root terminator */
            if (out_len > 0 && out_name[out_len - 1] == '.') {
                out_name[out_len - 1] = '\0';
            } else if (out_len < max_name_len) {
                out_name[out_len] = '\0';
            }
            if (jumps == 0) *inout_offset = offset;
            else *inout_offset = orig_offset;
            return (out_len > 0);
        }

        if ((len & 0xC0) == 0xC0) {
            /* Compression pointer */
            if (offset >= packet_len) return false;
            uint16_t ptr = (uint16_t)(((len & 0x3F) << 8) | packet[offset++]);
            if (jumps == 0) orig_offset = offset;
            jumps++;
            if (jumps > 16 || ptr >= packet_len) return false; /* loop or out-of-bounds */
            offset = ptr;
            continue;
        }

        if (offset + len > packet_len) return false;

        for (uint8_t i = 0; i < len; i++) {
            if (out_len + 1 < max_name_len) {
                out_name[out_len++] = (char)tolower(packet[offset + i]);
            }
        }
        offset += len;

        if (out_len + 1 < max_name_len) {
            out_name[out_len++] = '.';
        }
    }

    return false;
}

void netcap_dns_cache_learn_response(netcap_dns_cache_t *c, const uint8_t *dns_payload, size_t len) {
    if (!c || !dns_payload || len < 12) return;

    /* Check Header */
    uint16_t flags = read_be16(dns_payload + 2);
    bool is_response = (flags & 0x8000) != 0;
    uint8_t rcode = (uint8_t)(flags & 0x000F);
    if (!is_response || rcode != 0) return; /* Only learn from successful responses */

    uint16_t qdcount = read_be16(dns_payload + 4);
    uint16_t ancount = read_be16(dns_payload + 6);
    if (ancount == 0) return;

    size_t offset = 12;
    char qname[MAX_DOMAIN_LEN] = {0};

    /* Skip Question Section, retaining the first QNAME */
    for (uint16_t q = 0; q < qdcount; q++) {
        char temp_qname[MAX_DOMAIN_LEN] = {0};
        if (!parse_wire_name(dns_payload, len, &offset, temp_qname, sizeof(temp_qname))) return;
        if (q == 0 && temp_qname[0]) {
            snprintf(qname, sizeof(qname), "%s", temp_qname);
        }
        if (offset + 4 > len) return;
        offset += 4; /* skip QTYPE and QCLASS */
    }

    if (qname[0] == '\0') return;

    /* Parse Answers */
    for (uint16_t a = 0; a < ancount && offset < len; a++) {
        char aname[MAX_DOMAIN_LEN] = {0};
        if (!parse_wire_name(dns_payload, len, &offset, aname, sizeof(aname))) return;

        if (offset + 10 > len) return;
        uint16_t type = read_be16(dns_payload + offset);
        /* uint16_t class = read_be16(dns_payload + offset + 2); */
        uint32_t ttl = read_be32(dns_payload + offset + 4);
        uint16_t rdlen = read_be16(dns_payload + offset + 8);
        offset += 10;

        if (offset + rdlen > len) return;

        if (type == 1 && rdlen == 4) {
            /* Type A: IPv4 */
            const uint8_t *ip4 = dns_payload + offset;
            /* Associate with the canonical QNAME queried */
            netcap_dns_cache_insert(c, ip4, 4, qname, ttl);
        } else if (type == 28 && rdlen == 16) {
            /* Type AAAA: IPv6 */
            const uint8_t *ip6 = dns_payload + offset;
            netcap_dns_cache_insert(c, ip6, 6, qname, ttl);
        }

        offset += rdlen;
    }
}
