#define _POSIX_C_SOURCE 200809L
#include "payload_buffer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

netcap_payload_buf_t *netcap_payload_buf_create(netcap_payload_mode_t mode) {
    if (mode == NETCAP_PAYLOAD_NONE) return NULL;
    netcap_payload_buf_t *pb = calloc(1, sizeof(*pb));
    if (!pb) return NULL;

    pb->mode = mode;
    pb->max_per_dir = (mode == NETCAP_PAYLOAD_MINIMAL) ? NETCAP_MINIMAL_PAYLOAD_LIMIT : NETCAP_FULL_PAYLOAD_LIMIT;
    pb->capacity_chunks = 16;
    pb->chunks = calloc(pb->capacity_chunks, sizeof(netcap_payload_chunk_t));
    if (!pb->chunks) {
        free(pb);
        return NULL;
    }
    return pb;
}

void netcap_payload_buf_destroy(netcap_payload_buf_t *pb) {
    if (!pb) return;
    for (uint32_t i = 0; i < pb->num_chunks; i++) {
        free(pb->chunks[i].data);
    }
    free(pb->chunks);
    free(pb);
}

void netcap_payload_buf_append(netcap_payload_buf_t *pb, bool is_tx,
                               const uint8_t *data, uint32_t len, uint64_t timestamp_ms) {
    if (!pb || !data || len == 0) return;

    uint32_t *stored = is_tx ? &pb->tx_stored : &pb->rx_stored;
    if (*stored >= pb->max_per_dir) return; /* Limit reached for this direction */

    uint32_t to_copy = len;
    if (*stored + to_copy > pb->max_per_dir) {
        to_copy = pb->max_per_dir - *stored;
    }

    if (to_copy == 0) return;

    /* Expand chunk array if needed */
    if (pb->num_chunks >= pb->capacity_chunks) {
        uint32_t new_cap = pb->capacity_chunks * 2;
        netcap_payload_chunk_t *new_chunks = realloc(pb->chunks, new_cap * sizeof(netcap_payload_chunk_t));
        if (!new_chunks) return;
        pb->chunks = new_chunks;
        pb->capacity_chunks = new_cap;
    }

    uint8_t *buf = malloc(to_copy);
    if (!buf) return;
    memcpy(buf, data, to_copy);

    pb->chunks[pb->num_chunks].is_tx = is_tx ? 1 : 0;
    pb->chunks[pb->num_chunks].len = to_copy;
    pb->chunks[pb->num_chunks].timestamp_ms = timestamp_ms;
    pb->chunks[pb->num_chunks].data = buf;
    pb->num_chunks++;

    *stored += to_copy;
}

uint32_t netcap_payload_buf_get(const netcap_payload_buf_t *pb, int dir,
                                uint8_t *out_buf, uint32_t max_len) {
    if (!pb || !out_buf || max_len == 0) return 0;
    uint32_t total = 0;

    for (uint32_t i = 0; i < pb->num_chunks; i++) {
        const netcap_payload_chunk_t *ch = &pb->chunks[i];
        if (dir == 1 && !ch->is_tx) continue;
        if (dir == 2 && ch->is_tx) continue;

        uint32_t to_write = ch->len;
        if (total + to_write > max_len) {
            to_write = max_len - total;
        }

        if (to_write > 0) {
            memcpy(out_buf + total, ch->data, to_write);
            total += to_write;
        }

        if (total >= max_len) break;
    }

    return total;
}

uint32_t netcap_payload_format_hex(const uint8_t *data, uint32_t len,
                                   char *out_str, uint32_t max_str_len) {
    if (!data || len == 0 || !out_str || max_str_len < 80) return 0;

    uint32_t written = 0;
    for (uint32_t i = 0; i < len; i += 16) {
        char line[128];
        int offset = snprintf(line, sizeof(line), "%08x  ", i);

        /* Hex bytes (16 bytes per line) */
        for (uint32_t j = 0; j < 16; j++) {
            if (i + j < len) {
                offset += snprintf(line + offset, sizeof(line) - offset, "%02x ", data[i + j]);
            } else {
                offset += snprintf(line + offset, sizeof(line) - offset, "   ");
            }
            if (j == 7) {
                offset += snprintf(line + offset, sizeof(line) - offset, " ");
            }
        }

        /* ASCII representation */
        offset += snprintf(line + offset, sizeof(line) - offset, " |");
        for (uint32_t j = 0; j < 16 && (i + j) < len; j++) {
            uint8_t c = data[i + j];
            offset += snprintf(line + offset, sizeof(line) - offset, "%c", isprint(c) ? c : '.');
        }
        offset += snprintf(line + offset, sizeof(line) - offset, "|\n");

        if (written + offset < max_str_len) {
            memcpy(out_str + written, line, offset);
            written += offset;
        } else {
            break;
        }
    }

    out_str[written] = '\0';
    return written;
}
