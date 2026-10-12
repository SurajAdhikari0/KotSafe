#ifndef NETCAP_DNS_SINKHOLE_H
#define NETCAP_DNS_SINKHOLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Checks if a given packet payload is a DNS Query.
 */
bool netcap_is_dns_query(uint8_t proto, uint16_t dst_port, const uint8_t *dns_payload, size_t len);

/**
 * Extracts the queried domain name (QNAME) from an RFC 1035 DNS query payload.
 */
bool netcap_dns_extract_qname(const uint8_t *dns_payload, size_t len, char *out_qname, size_t max_len);

/**
 * Synthesizes an RFC 1035 Sinkhole Response (0.0.0.0 for A, :: for AAAA)
 * formatted as a complete IPv4/IPv6 + UDP packet ready for direct write to tun_fd.
 *
 * @param query_packet The raw inbound packet from TUN (IP + UDP + DNS)
 * @param packet_len Total length of query_packet
 * @param ip_hdr_len IP header length (20 for IPv4, 40 for IPv6)
 * @param family 4 for IPv4, 6 for IPv6
 * @param out_pkt Buffer to receive synthesized packet
 * @param max_out_len Buffer capacity (must be >= 512)
 * @return Total bytes of synthesized packet, or 0 on error
 */
size_t netcap_dns_synthesize_sinkhole_packet(const uint8_t *query_packet, size_t packet_len,
                                             size_t ip_hdr_len, uint8_t family,
                                             uint8_t *out_pkt, size_t max_out_len);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_DNS_SINKHOLE_H */
