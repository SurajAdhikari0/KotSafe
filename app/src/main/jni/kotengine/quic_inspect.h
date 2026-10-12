#ifndef NETCAP_QUIC_INSPECT_H
#define NETCAP_QUIC_INSPECT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char domain[256];
    uint32_t quic_version;
    bool is_gquic;
    bool has_sni;
} netcap_quic_info_t;

/*
 * Inspects a UDP payload on port 443 (or any UDP port) to determine if it is a QUIC Initial / CHLO packet.
 * If so, extracts the SNI (Server Name Indication) domain and QUIC version.
 * Returns true if QUIC packet was identified and parsed, false otherwise.
 */
bool netcap_quic_inspect(const uint8_t *payload, size_t payload_len, netcap_quic_info_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_QUIC_INSPECT_H */
