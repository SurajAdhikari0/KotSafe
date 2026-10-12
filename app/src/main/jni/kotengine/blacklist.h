#ifndef NETCAP_BLACKLIST_H
#define NETCAP_BLACKLIST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * blacklist: a binary (radix) trie over IP address bits, one trie for
 * IPv4 (32 levels) and one for IPv6 (128 levels). A "blocked" flag is
 * set on the node at the end of each configured CIDR prefix; matching
 * a packet's address walks bit-by-bit from the root and returns true
 * as soon as any ancestor (or the exact node) is marked blocked.
 *
 * This gives O(prefix_len) matching - at most 32 or 128 pointer hops -
 * regardless of how many rules are loaded, versus O(rule_count) for a
 * linear list-of-CIDRs scan. For the rule-set sizes these apps use
 * (tens to low thousands of entries) this is a meaningful win when
 * matching happens on every packet.
 */

typedef struct netcap_blacklist netcap_blacklist_t;

netcap_blacklist_t *netcap_blacklist_create(void);
void netcap_blacklist_destroy(netcap_blacklist_t *bl);

/* Adds a CIDR rule, e.g. addr = 4 bytes for IPv4 or 16 bytes for IPv6,
 * prefix_len in [0,32] or [0,128] respectively. */
void netcap_blacklist_add(netcap_blacklist_t *bl, const uint8_t *addr,
                           uint8_t family, uint8_t prefix_len);

void netcap_blacklist_remove_all(netcap_blacklist_t *bl, uint8_t family);

/* Returns 1 if addr falls under any blocked prefix, else 0. */
int netcap_blacklist_match(const netcap_blacklist_t *bl, const uint8_t *addr, uint8_t family);

size_t netcap_blacklist_rule_count(const netcap_blacklist_t *bl, uint8_t family);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_BLACKLIST_H */
