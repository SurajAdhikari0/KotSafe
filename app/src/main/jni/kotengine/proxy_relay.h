#ifndef NETCAP_PROXY_RELAY_H
#define NETCAP_PROXY_RELAY_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct netcap_proxy_relay netcap_proxy_relay_t;

netcap_proxy_relay_t *netcap_proxy_relay_create(void);
void netcap_proxy_relay_destroy(netcap_proxy_relay_t *pr);

/*
 * Adds or replaces a port redirection rule:
 * proto: NETCAP_PROTO_TCP (6) or NETCAP_PROTO_UDP (17)
 * orig_port: destination port to intercept (e.g. 80, 443)
 * redirect_port: target proxy port (e.g. 8080)
 * redirect_ip: target proxy IP (e.g. "127.0.0.1")
 * Returns 0 on success, -1 on error.
 */
int netcap_proxy_relay_add_rule(netcap_proxy_relay_t *pr, uint8_t proto,
                                uint16_t orig_port, uint16_t redirect_port,
                                const char *redirect_ip);

/* Removes a redirection rule */
void netcap_proxy_relay_remove_rule(netcap_proxy_relay_t *pr, uint8_t proto, uint16_t orig_port);

/* Clears all redirection rules */
void netcap_proxy_relay_clear_rules(netcap_proxy_relay_t *pr);

/* Sets application UIDs exempt from proxy redirection (prevents loops) */
void netcap_proxy_relay_set_exempt_uids(netcap_proxy_relay_t *pr, const int32_t *uids, uint32_t count);

/*
 * Checks if a flow matches any redirection rule and is not exempt by UID.
 * If matched, returns true and fills out_dst_ip, out_dst_port, out_family.
 */
bool netcap_proxy_relay_match(const netcap_proxy_relay_t *pr, int32_t uid,
                              uint8_t proto, uint16_t orig_port,
                              uint8_t out_dst_ip[16], uint16_t *out_dst_port,
                              uint8_t *out_family);

/*
 * If matched and not exempt, rewrites dst IP and port directly inside the packet buffer
 * and recomputes the necessary IP and TCP checksums.
 * Returns true if rewritten, false if untouched.
 */
bool netcap_proxy_relay_rewrite_packet(const netcap_proxy_relay_t *pr, int32_t uid,
                                       uint8_t *pkt, uint32_t len, uint32_t ip_hdr_len,
                                       uint8_t proto, uint8_t family,
                                       uint8_t out_redir_ip[16], uint16_t *out_redir_port);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_PROXY_RELAY_H */
