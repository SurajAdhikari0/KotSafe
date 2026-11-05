#ifndef NETCAP_NETWORK_POLICY_H
#define NETCAP_NETWORK_POLICY_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct netcap_network_policy netcap_network_policy_t;
enum { NETCAP_POLICY_DENY = 0, NETCAP_POLICY_ALLOW = 1, NETCAP_POLICY_FEED = 2 };
netcap_network_policy_t *netcap_network_policy_create(void);
void netcap_network_policy_destroy(netcap_network_policy_t *policy);
/* Build first, then swap one independently owned source. Failure preserves the old source. */
bool netcap_network_policy_replace(netcap_network_policy_t *policy, int source, bool enabled,
    const int32_t *uids, size_t uid_count, const char *const *domains, size_t domain_count,
    const char *const *cidrs, size_t cidr_count);
/* Explicit deny/feed matches take precedence over allow rules. Unknown UIDs default-deny
 * in allowlist mode unless the destination itself is allowed. */
bool netcap_network_policy_blocks(netcap_network_policy_t *policy, int32_t uid,
    const uint8_t *ip, uint8_t family, const char *domain);
#endif
