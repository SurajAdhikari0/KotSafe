#ifndef NETCAP_DNS_CACHE_H
#define NETCAP_DNS_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct netcap_dns_cache netcap_dns_cache_t;

/**
 * Creates a thread-safe DNS reverse IP cache with the given capacity.
 * Capacity defaults to 2048 if 0 is passed.
 */
netcap_dns_cache_t *netcap_dns_cache_create(uint32_t capacity);

/**
 * Destroys the DNS cache and frees all associated memory.
 */
void netcap_dns_cache_destroy(netcap_dns_cache_t *cache);

/**
 * Clears all entries in the cache.
 */
void netcap_dns_cache_clear(netcap_dns_cache_t *cache);

/**
 * Looks up an IP address (IPv4 or IPv6) in the cache.
 * Returns true and writes null-terminated domain to out_domain if found and unexpired.
 */
bool netcap_dns_cache_lookup(netcap_dns_cache_t *cache, const uint8_t *ip, uint8_t family,
                             char *out_domain, size_t max_len);

/**
 * Explicitly inserts an IP-to-Domain mapping into the cache with given TTL in seconds.
 */
void netcap_dns_cache_insert(netcap_dns_cache_t *cache, const uint8_t *ip, uint8_t family,
                             const char *domain, uint32_t ttl_secs);

/**
 * Learns IP-to-Domain mappings by parsing an RFC 1035 DNS response payload.
 * Automatically extracts Type A (IPv4) and Type AAAA (IPv6) resource records
 * and associates them with the question domain name.
 */
void netcap_dns_cache_learn_response(netcap_dns_cache_t *cache, const uint8_t *dns_payload, size_t len);

/**
 * Returns current count of valid cached entries.
 */
uint32_t netcap_dns_cache_size(netcap_dns_cache_t *cache);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_DNS_CACHE_H */
