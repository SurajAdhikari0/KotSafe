#define _GNU_SOURCE
#include "quic_inspect.h"
#include <string.h>
#include <ctype.h>

static inline uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t get_le32(const uint8_t *p) {
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static inline uint16_t get_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static bool is_valid_domain_char(char c) {
    return (isalnum((unsigned char)c) || c == '.' || c == '-' || c == '_');
}

/* Parses TLS Handshake ClientHello (without 5-byte record layer) */
static bool parse_raw_tls_client_hello(const uint8_t *data, size_t len, char *out_domain, size_t max_len) {
    if (len < 38) return false;

    /* Handshake Type must be ClientHello (0x01) */
    if (data[0] != 0x01) return false;

    size_t offset = 4; /* skip type (1) + length (3) */

    /* Client version: 2 bytes (0x03 0x03) */
    if (offset + 2 > len) return false;
    offset += 2;

    /* Client Random: 32 bytes */
    if (offset + 32 > len) return false;
    offset += 32;

    /* Session ID */
    if (offset >= len) return false;
    uint8_t sid_len = data[offset++];
    if (offset + sid_len > len) return false;
    offset += sid_len;

    /* Cipher Suites */
    if (offset + 2 > len) return false;
    uint16_t cs_len = get_be16(data + offset);
    offset += 2;
    if (offset + cs_len > len) return false;
    offset += cs_len;

    /* Compression Methods */
    if (offset >= len) return false;
    uint8_t comp_len = data[offset++];
    if (offset + comp_len > len) return false;
    offset += comp_len;

    /* Extensions */
    if (offset + 2 > len) return false;
    uint16_t ext_len = get_be16(data + offset);
    offset += 2;

    size_t ext_end = offset + ext_len;
    if (ext_end > len) ext_end = len;

    while (offset + 4 <= ext_end) {
        uint16_t ext_type = get_be16(data + offset);
        uint16_t ext_val_len = get_be16(data + offset + 2);
        offset += 4;

        if (offset + ext_val_len > ext_end) break;

        if (ext_type == 0x0000 /* Server Name Indication */) {
            if (ext_val_len < 5) return false;
            uint16_t sni_list_len = get_be16(data + offset);
            (void)sni_list_len;

            uint8_t name_type = data[offset + 2];
            if (name_type == 0x00 /* host_name */) {
                uint16_t name_len = get_be16(data + offset + 3);
                if (offset + 5 + name_len > ext_end) return false;
                if (name_len == 0 || name_len >= max_len) return false;

                const char *src = (const char *)(data + offset + 5);
                for (uint16_t i = 0; i < name_len; i++) {
                    if (!is_valid_domain_char(src[i])) return false;
                    out_domain[i] = (char)tolower((unsigned char)src[i]);
                }
                out_domain[name_len] = '\0';
                return true;
            }
        }
        offset += ext_val_len;
    }
    return false;
}

/* Parses Google QUIC (gQUIC) CHLO packet */
static bool parse_gquic_chlo(const uint8_t *payload, size_t len, char *out_domain, size_t max_len) {
    if (len < 12) return false;

    /* Scan for 'CHLO' tag */
    const uint8_t *chlo = NULL;
    for (size_t i = 0; i + 4 <= len && i < 128; i++) {
        if (payload[i] == 'C' && payload[i+1] == 'H' && payload[i+2] == 'L' && payload[i+3] == 'O') {
            chlo = payload + i;
            break;
        }
    }
    if (!chlo) return false;

    size_t rem = len - (chlo - payload);
    if (rem < 8) return false;

    uint16_t num_tags = get_le16(chlo + 4);
    /* 2 reserved padding bytes at chlo + 6 */

    size_t header_size = 8 + (size_t)num_tags * 8;
    if (rem < header_size) return false;

    const uint8_t *tag_entries = chlo + 8;
    const uint8_t *tag_data = chlo + header_size;
    size_t tag_data_len = rem - header_size;

    uint32_t prev_offset = 0;
    for (uint16_t i = 0; i < num_tags; i++) {
        const uint8_t *entry = tag_entries + (i * 8);
        uint32_t end_offset = get_le32(entry + 4);

        if (entry[0] == 'S' && entry[1] == 'N' && entry[2] == 'I' && (entry[3] == '\0' || entry[3] == ' ')) {
            if (end_offset > tag_data_len || end_offset <= prev_offset) return false;
            size_t sni_len = end_offset - prev_offset;
            if (sni_len == 0 || sni_len >= max_len) return false;

            const char *src = (const char *)(tag_data + prev_offset);
            for (size_t k = 0; k < sni_len; k++) {
                if (!is_valid_domain_char(src[k])) return false;
                out_domain[k] = (char)tolower((unsigned char)src[k]);
            }
            out_domain[sni_len] = '\0';
            return true;
        }
        prev_offset = end_offset;
    }
    return false;
}

bool netcap_quic_inspect(const uint8_t *payload, size_t len, netcap_quic_info_t *out) {
    if (!payload || len < 16 || !out) return false;
    memset(out, 0, sizeof(*out));

    /* 1. Check for Google QUIC (gQUIC) */
    if (parse_gquic_chlo(payload, len, out->domain, sizeof(out->domain))) {
        out->is_gquic = true;
        out->has_sni = true;
        return true;
    }

    /* 2. Check for IETF QUIC Long Header Initial (RFC 9000) */
    uint8_t first_byte = payload[0];
    if (first_byte & 0x80) {
        /* Long Header */
        uint32_t version = (uint32_t)((payload[1] << 24) | (payload[2] << 16) | (payload[3] << 8) | payload[4]);
        out->quic_version = version;

        /* Scan payload for unencrypted TLS 1.3 ClientHello */
        for (size_t i = 5; i + 40 <= len; i++) {
            if (payload[i] == 0x01 && payload[i+4] == 0x03 && payload[i+5] == 0x03) {
                if (parse_raw_tls_client_hello(payload + i, len - i, out->domain, sizeof(out->domain))) {
                    out->has_sni = true;
                    return true;
                }
            }
        }
    }

    return false;
}
