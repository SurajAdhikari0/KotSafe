#ifndef NETCAP_FIREWALL_H
#define NETCAP_FIREWALL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct netcap_firewall netcap_firewall_t;

/**
 * Creates a new high-performance firewall engine instance.
 */
netcap_firewall_t *netcap_firewall_create(void);

/**
 * Destroys the firewall instance and frees all allocated memory.
 */
void netcap_firewall_destroy(netcap_firewall_t *fw);

/**
 * Configures the list of Android app UIDs completely blocked from internet access.
 */
void netcap_firewall_set_blocked_uids(netcap_firewall_t *fw, const int32_t *uids, uint32_t count);

/**
 * Checks if a specific UID is firewalled.
 */
bool netcap_firewall_is_uid_blocked(const netcap_firewall_t *fw, int32_t uid);

/**
 * Adds a domain name to the blocklist (supports exact and suffix match, e.g. "doubleclick.net"
 * blocks "doubleclick.net" and "ad.doubleclick.net").
 */
void netcap_firewall_add_blocked_domain(netcap_firewall_t *fw, const char *domain);

/**
 * Removes a domain name from the blocklist.
 */
void netcap_firewall_remove_blocked_domain(netcap_firewall_t *fw, const char *domain);

/**
 * Clears all blocked domains from the firewall.
 */
void netcap_firewall_clear_blocked_domains(netcap_firewall_t *fw);

/**
 * Checks if a domain is blocked by the firewall.
 */
bool netcap_firewall_is_domain_blocked(const netcap_firewall_t *fw, const char *domain);

/**
 * Returns the total count of blocked domains.
 */
uint32_t netcap_firewall_blocked_domains_count(const netcap_firewall_t *fw);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_FIREWALL_H */
