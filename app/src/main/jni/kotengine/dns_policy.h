#ifndef NETCAP_DNS_POLICY_H
#define NETCAP_DNS_POLICY_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct netcap_dns_policy netcap_dns_policy_t;

netcap_dns_policy_t *netcap_dns_policy_create(void);
void netcap_dns_policy_destroy(netcap_dns_policy_t *pol);

/*
 * Block Private DNS (DoT / Port 853).
 * When enabled, drops outbound packets to port 853 so Android falls back to standard DNS (port 53).
 */
void netcap_dns_policy_set_block_dot(netcap_dns_policy_t *pol, bool block);
bool netcap_dns_policy_is_dot_blocked(const netcap_dns_policy_t *pol);

/*
 * Custom DNS Server Redirection.
 * Pass NULL to clear/disable custom DNS redirection.
 * Returns 0 on success, -1 on invalid IP.
 */
int netcap_dns_policy_set_custom_dns(netcap_dns_policy_t *pol, const char *dns_ip);
bool netcap_dns_policy_get_custom_dns(const netcap_dns_policy_t *pol, uint8_t out_ip[16], uint8_t *out_family);

/*
 * Per-App LAN Isolation / Access Control.
 * Configures the list of Android app UIDs forbidden from communicating with LAN / private subnets.
 */
void netcap_dns_policy_set_lan_blocked_uids(netcap_dns_policy_t *pol, const int32_t *uids, uint32_t count);
bool netcap_dns_policy_is_lan_blocked(const netcap_dns_policy_t *pol, int32_t uid, const uint8_t *dst_ip, uint8_t family);

/*
 * Rewrites a DNS request packet (UDP port 53) to redirect to the configured custom DNS server.
 * Returns true if packet was rewritten, false otherwise.
 */
bool netcap_dns_policy_rewrite_dns_packet(const netcap_dns_policy_t *pol, uint8_t *pkt, uint32_t len, uint32_t ip_hdr_len, uint8_t family);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_DNS_POLICY_H */
