#ifndef NETCAP_PCAPNG_SECRETS_H
#define NETCAP_PCAPNG_SECRETS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "pcapng_writer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PCAPNG_DSB_TYPE 0x0000000Au
#define PCAPNG_DSB_SECRETS_TLS 0x544c534bu      /* 'TLSK' = TLS Key Log */
#define PCAPNG_DSB_SECRETS_WIREGUARD 0x57474b4cu/* 'WGKL' = WireGuard Key Log */

typedef struct netcap_secrets_store netcap_secrets_store_t;

/* Create a new secrets store to hold and broadcast TLS/decryption keys */
netcap_secrets_store_t *netcap_secrets_create(size_t max_entries);

/* Free the secrets store */
void netcap_secrets_destroy(netcap_secrets_store_t *store);

/* Add a TLS Key Log line (e.g., "CLIENT_RANDOM <random> <master_secret>") */
int netcap_secrets_add_tls_key(netcap_secrets_store_t *store, const char *keylog_line);

/* Build a binary PCAPng DSB block from raw secret data.
 * Returns total block length written to out_buf, or needed length if out_buf is NULL/too small. */
size_t netcap_pcapng_build_dsb(uint32_t secrets_type, const uint8_t *data, uint32_t data_len,
                               uint8_t *out_buf, size_t out_cap);

/* Write DSB directly to a FILE stream (e.g. pcapng file) */
int netcap_pcapng_write_dsb_file(FILE *fp, uint32_t secrets_type, const uint8_t *data, uint32_t data_len);

/* Dump all cached secrets as DSB blocks to a stream (e.g., when a new Wireshark client connects) */
int netcap_secrets_dump_all_to_fd(netcap_secrets_store_t *store, int sock_fd);

/* Dump all cached secrets to a pcapng writer */
int netcap_secrets_dump_all_to_file(netcap_secrets_store_t *store, FILE *fp);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_PCAPNG_SECRETS_H */
