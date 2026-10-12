#ifndef NETCAP_PAYLOAD_BUFFER_H
#define NETCAP_PAYLOAD_BUFFER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NETCAP_PAYLOAD_NONE = 0,
    NETCAP_PAYLOAD_MINIMAL = 1, /* First 512 bytes Tx and Rx */
    NETCAP_PAYLOAD_FULL = 2     /* Up to 32KB per connection */
} netcap_payload_mode_t;

#define NETCAP_MINIMAL_PAYLOAD_LIMIT 512
#define NETCAP_FULL_PAYLOAD_LIMIT    32768

typedef struct {
    uint8_t is_tx;
    uint32_t len;
    uint64_t timestamp_ms;
    uint8_t *data;
} netcap_payload_chunk_t;

typedef struct netcap_payload_buf {
    netcap_payload_mode_t mode;
    uint32_t tx_stored;
    uint32_t rx_stored;
    uint32_t max_per_dir;

    netcap_payload_chunk_t *chunks;
    uint32_t num_chunks;
    uint32_t capacity_chunks;
} netcap_payload_buf_t;

netcap_payload_buf_t *netcap_payload_buf_create(netcap_payload_mode_t mode);
void netcap_payload_buf_destroy(netcap_payload_buf_t *pb);

/* Appends payload chunk respecting mode limits */
void netcap_payload_buf_append(netcap_payload_buf_t *pb, bool is_tx,
                               const uint8_t *data, uint32_t len, uint64_t timestamp_ms);

/*
 * Dumps payload data into out_buf.
 * dir: 0 = chronological all, 1 = Tx only (client requests), 2 = Rx only (server responses)
 * Returns total bytes copied.
 */
uint32_t netcap_payload_buf_get(const netcap_payload_buf_t *pb, int dir,
                                uint8_t *out_buf, uint32_t max_len);

/*
 * Formats a binary payload buffer into a Wireshark-style Hex+ASCII view:
 * "00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|\n"
 */
uint32_t netcap_payload_format_hex(const uint8_t *data, uint32_t len,
                                   char *out_str, uint32_t max_str_len);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_PAYLOAD_BUFFER_H */
