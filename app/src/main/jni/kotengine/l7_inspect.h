#ifndef NETCAP_L7_INSPECT_H
#define NETCAP_L7_INSPECT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ja4.h"
#include "entropy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NETCAP_DOMAIN_MAX 128
#define NETCAP_PROTO_NAME_MAX 16

typedef struct {
    char domain[NETCAP_DOMAIN_MAX];
    char protocol[NETCAP_PROTO_NAME_MAX];
    char ja4[JA4_STRING_LEN];
    float entropy;
    bool is_encrypted_entropy;
    bool is_suspicious_entropy;
    bool has_domain;
    bool has_protocol;
    bool has_ja4;
    bool has_entropy;
} netcap_l7_info_t;

/**
 * Inspects a packet payload (after L3/L4 headers have been stripped).
 * Extracts hostname / SNI / QNAME, protocol identification, JA4 fingerprint,
 * and calculates real-time Shannon entropy.
 * 
 * Returns true if any L7 metadata was successfully extracted.
 */
bool netcap_l7_inspect(uint8_t ip_proto, uint16_t src_port, uint16_t dst_port,
                       const uint8_t *payload, size_t payload_len,
                       netcap_l7_info_t *out_info);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_L7_INSPECT_H */
