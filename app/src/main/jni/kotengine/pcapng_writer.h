#ifndef NETCAP_PCAPNG_WRITER_H
#define NETCAP_PCAPNG_WRITER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal PCAPng writer: Section Header Block + one Interface Description
 * Block + a stream of Enhanced Packet Blocks. PCAPng (vs. classic PCAP)
 * is used because it supports per-packet interface metadata and is the
 * format Wireshark prefers for new captures.
 *
 * Writes are buffered internally and flushed in chunks so the capture
 * hot path isn't doing a write() syscall per packet.
 */

typedef struct netcap_pcapng_writer netcap_pcapng_writer_t;

/* Opens `path` for writing and emits the Section Header + Interface
 * Description blocks. snaplen bounds how many bytes of each packet are
 * stored (0 = unlimited within uint32 range). Returns NULL on failure. */
netcap_pcapng_writer_t *netcap_pcapng_open(const char *path, const char *if_name,
                                            uint32_t snaplen);

/* Appends one Enhanced Packet Block. `ts_us` = capture timestamp in
 * microseconds since epoch. `orig_len` is the true on-wire length even
 * if `data_len` was truncated to snaplen. Returns 0 on success. */
int netcap_pcapng_write_packet(netcap_pcapng_writer_t *w, uint64_t ts_us,
                                const uint8_t *data, uint32_t data_len,
                                uint32_t orig_len);

/* Flushes buffered output to disk without closing. */
int netcap_pcapng_flush(netcap_pcapng_writer_t *w);

/* Access internal file handle for embedding blocks like DSBs */
FILE *netcap_pcapng_get_fp(netcap_pcapng_writer_t *w);

void netcap_pcapng_close(netcap_pcapng_writer_t *w);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_PCAPNG_WRITER_H */
