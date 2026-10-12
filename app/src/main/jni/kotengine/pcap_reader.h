#ifndef NETCAP_PCAP_READER_H
#define NETCAP_PCAP_READER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * pcap_reader: offline replay source, mirroring the original's
 * capture_pcap.c role - feeds previously-captured packets through the
 * same parse/track/blacklist pipeline as live TUN capture, for
 * analyzing a saved capture without a device attached. Reads classic
 * PCAP (both byte orders) and PCAPng (Section Header + Enhanced or
 * legacy Packet Blocks).
 */

typedef struct netcap_pcap_reader netcap_pcap_reader_t;

/* Opens `path` and auto-detects PCAP vs PCAPng by magic number. Returns
 * NULL if the file can't be opened or doesn't match either format. */
netcap_pcap_reader_t *netcap_pcap_reader_open(const char *path);

/* Reads the next packet. Returns 1 with data/len/ts_us set (data
 * points into an internal buffer valid until the next call), 0 at EOF,
 * -1 on a malformed record. */
int netcap_pcap_reader_next(netcap_pcap_reader_t *r,
                             const uint8_t **data, uint32_t *len, uint64_t *ts_us);

void netcap_pcap_reader_close(netcap_pcap_reader_t *r);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_PCAP_READER_H */
