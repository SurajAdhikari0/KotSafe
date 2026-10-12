#define _GNU_SOURCE
#include "l7_inspect.h"
#include "quic_inspect.h"
#include "ja4.h"
#include "entropy.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_ALPN 0x0010
#define TLS_NAME_TYPE_HOSTNAME 0x00

/* Safely read 16-bit big-endian unsigned int */
static inline uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* Parses TLS ClientHello to extract SNI, ciphers, extensions, ALPN, and JA4 */
static bool parse_tls_client_hello(const uint8_t *data, size_t len,
                                   char *out_domain, size_t max_len,
                                   char *out_ja4, size_t ja4_max_len) {
    if (len < 5) return false;

    /* TLS Record Header */
    if (data[0] != TLS_CONTENT_TYPE_HANDSHAKE) return false;
    uint16_t record_len = get_be16(data + 3);
    (void)record_len;

    size_t offset = 5;
    if (offset >= len) return false;

    /* Handshake Header */
    if (data[offset] != TLS_HANDSHAKE_CLIENT_HELLO) return false;
    if (offset + 4 > len) return false;
    offset += 4;

    /* Client version (2 bytes) */
    if (offset + 2 > len) return false;
    uint16_t tls_version = get_be16(data + offset);
    offset += 2;

    /* Client Random: 32 bytes */
    if (offset + 32 > len) return false;
    offset += 32;

    /* Session ID */
    if (offset >= len) return false;
    uint8_t session_id_len = data[offset++];
    if (offset + session_id_len > len) return false;
    offset += session_id_len;

    /* Cipher Suites */
    if (offset + 2 > len) return false;
    uint16_t cipher_suites_len = get_be16(data + offset);
    offset += 2;
    if (offset + cipher_suites_len > len) return false;

    uint16_t ciphers[128];
    size_t num_ciphers = 0;
    for (size_t i = 0; i + 1 < cipher_suites_len && num_ciphers < 128; i += 2) {
        ciphers[num_ciphers++] = get_be16(data + offset + i);
    }
    offset += cipher_suites_len;

    /* Compression Methods */
    if (offset >= len) return false;
    uint8_t compression_len = data[offset++];
    if (offset + compression_len > len) return false;
    offset += compression_len;

    /* Extensions */
    if (offset + 2 > len) return false;
    uint16_t extensions_len = get_be16(data + offset);
    offset += 2;

    size_t ext_end = offset + extensions_len;
    if (ext_end > len) ext_end = len;

    uint16_t extensions[128];
    size_t num_extensions = 0;
    bool found_sni = false;
    char alpn_buf[32] = {0};

    while (offset + 4 <= ext_end) {
        uint16_t ext_type = get_be16(data + offset);
        uint16_t ext_len = get_be16(data + offset + 2);
        offset += 4;

        if (offset + ext_len > ext_end) break;

        if (num_extensions < 128) {
            extensions[num_extensions++] = ext_type;
        }

        /* Check for supported_versions (0x002b) which signals TLS 1.3 */
        if (ext_type == 0x002b && ext_len >= 2) {
            uint8_t sv_len = data[offset];
            for (size_t s = 1; s + 1 <= sv_len && offset + s + 1 <= ext_end; s += 2) {
                uint16_t ver = get_be16(data + offset + s);
                if (ver == 0x0304) {
                    tls_version = 0x0304;
                    break;
                }
            }
        }

        /* Server Name Indication (SNI) */
        if (ext_type == TLS_EXT_SERVER_NAME && ext_len >= 2) {
            size_t sn_offset = offset + 2;
            size_t sn_end = offset + ext_len;

            while (sn_offset + 3 <= sn_end) {
                uint8_t name_type = data[sn_offset];
                uint16_t name_len = get_be16(data + sn_offset + 1);
                sn_offset += 3;

                if (sn_offset + name_len > sn_end) break;

                if (name_type == TLS_NAME_TYPE_HOSTNAME) {
                    size_t to_copy = (name_len < max_len - 1) ? name_len : max_len - 1;
                    memcpy(out_domain, data + sn_offset, to_copy);
                    out_domain[to_copy] = '\0';
                    found_sni = true;
                    break;
                }
                sn_offset += name_len;
            }
        }

        /* ALPN (0x0010) */
        if (ext_type == TLS_EXT_ALPN && ext_len >= 3) {
            uint16_t alpn_list_len = get_be16(data + offset);
            if (alpn_list_len >= 1 && offset + 2 < ext_end) {
                uint8_t first_proto_len = data[offset + 2];
                if (offset + 3 + first_proto_len <= ext_end) {
                    size_t cp = first_proto_len < sizeof(alpn_buf) - 1 ? first_proto_len : sizeof(alpn_buf) - 1;
                    memcpy(alpn_buf, data + offset + 3, cp);
                    alpn_buf[cp] = '\0';
                }
            }
        }

        offset += ext_len;
    }

    /* Compute JA4 Fingerprint */
    if (out_ja4 && ja4_max_len >= JA4_STRING_LEN) {
        kotengine_ja4_t ja4_res = kotengine_generate_ja4(false, tls_version, found_sni,
                                                         ciphers, num_ciphers,
                                                         extensions, num_extensions,
                                                         alpn_buf[0] ? alpn_buf : NULL);
        if (ja4_res.valid) {
            snprintf(out_ja4, ja4_max_len, "%s", ja4_res.ja4);
        }
    }

    return found_sni || (num_ciphers > 0);
}

/* Parses DNS Query to extract QNAME */
static bool parse_dns_qname(const uint8_t *data, size_t len, char *out_domain, size_t max_len) {
    if (len < 12) return false;

    uint16_t qdcount = get_be16(data + 4);
    if (qdcount == 0) return false;

    size_t offset = 12;
    size_t out_idx = 0;

    while (offset < len) {
        uint8_t label_len = data[offset++];
        if (label_len == 0) {
            if (out_idx > 0 && out_domain[out_idx - 1] == '.') {
                out_domain[out_idx - 1] = '\0';
            } else {
                out_domain[out_idx] = '\0';
            }
            return (out_idx > 0);
        }

        if ((label_len & 0xC0) == 0xC0) {
            if (out_idx > 0 && out_domain[out_idx - 1] == '.') {
                out_domain[out_idx - 1] = '\0';
            } else {
                out_domain[out_idx] = '\0';
            }
            return (out_idx > 0);
        }

        if (offset + label_len > len) return false;

        for (uint8_t i = 0; i < label_len; i++) {
            if (out_idx + 1 < max_len) {
                out_domain[out_idx++] = (char)data[offset + i];
            }
        }
        offset += label_len;

        if (out_idx + 1 < max_len) {
            out_domain[out_idx++] = '.';
        }
    }

    return false;
}

/* Parses HTTP Request to extract Host: header */
static bool parse_http_host(const uint8_t *data, size_t len, char *out_domain, size_t max_len) {
    if (len < 10) return false;

    bool is_http = false;
    if (len >= 4 && memcmp(data, "GET ", 4) == 0) is_http = true;
    else if (len >= 5 && memcmp(data, "POST ", 5) == 0) is_http = true;
    else if (len >= 5 && memcmp(data, "HEAD ", 5) == 0) is_http = true;
    else if (len >= 4 && memcmp(data, "PUT ", 4) == 0) is_http = true;
    else if (len >= 7 && memcmp(data, "DELETE ", 7) == 0) is_http = true;
    else if (len >= 8 && memcmp(data, "CONNECT ", 8) == 0) is_http = true;
    else if (len >= 8 && memcmp(data, "OPTIONS ", 8) == 0) is_http = true;

    if (!is_http) return false;

    const char *p = (const char *)data;
    size_t remaining = len;

    while (remaining > 6) {
        if ((p[0] == '\r' && p[1] == '\n' && remaining >= 8 && strncasecmp(p + 2, "Host:", 5) == 0) ||
            (p[0] == '\n' && remaining >= 7 && strncasecmp(p + 1, "Host:", 5) == 0)) {
            
            const char *val = (p[0] == '\r') ? p + 7 : p + 6;
            remaining -= (val - p);
            p = val;

            while (remaining > 0 && (*p == ' ' || *p == '\t')) { p++; remaining--; }

            size_t out_idx = 0;
            while (remaining > 0 && *p != '\r' && *p != '\n' && *p != ' ' && *p != ':') {
                if (out_idx + 1 < max_len) {
                    out_domain[out_idx++] = *p;
                }
                p++;
                remaining--;
            }
            out_domain[out_idx] = '\0';
            return (out_idx > 0);
        }
        p++;
        remaining--;
    }

    return false;
}

bool netcap_l7_inspect(uint8_t ip_proto, uint16_t src_port, uint16_t dst_port,
                       const uint8_t *payload, size_t payload_len,
                       netcap_l7_info_t *out_info) {
    if (!payload || payload_len == 0 || !out_info) return false;
    memset(out_info, 0, sizeof(*out_info));

    /* Always compute Shannon entropy on payloads >= 16 bytes */
    if (payload_len >= 16) {
        kotengine_entropy_result_t ent = kotengine_analyze_entropy(payload, payload_len);
        out_info->entropy = ent.entropy;
        out_info->is_encrypted_entropy = ent.is_encrypted;
        out_info->is_suspicious_entropy = ent.is_suspicious;
        out_info->has_entropy = true;
    }

    /* 1. DNS (Port 53 UDP or TCP) */
    if (dst_port == 53 || src_port == 53) {
        snprintf(out_info->protocol, sizeof(out_info->protocol), "DNS");
        out_info->has_protocol = true;

        const uint8_t *dns_payload = payload;
        size_t dns_len = payload_len;
        if (ip_proto == 6 && payload_len > 2) {
            dns_payload += 2;
            dns_len -= 2;
        }

        if (parse_dns_qname(dns_payload, dns_len, out_info->domain, sizeof(out_info->domain))) {
            out_info->has_domain = true;
        }
        return true;
    }

    /* 2. TLS SNI & JA4 (Usually Port 443, but check payload handshake signature) */
    if (payload_len > 5 && payload[0] == TLS_CONTENT_TYPE_HANDSHAKE) {
        if (parse_tls_client_hello(payload, payload_len,
                                   out_info->domain, sizeof(out_info->domain),
                                   out_info->ja4, sizeof(out_info->ja4))) {
            snprintf(out_info->protocol, sizeof(out_info->protocol), "TLS");
            out_info->has_protocol = true;
            if (out_info->domain[0]) out_info->has_domain = true;
            if (out_info->ja4[0]) out_info->has_ja4 = true;
            return true;
        }
    }

    /* 3. HTTP (Port 80 or typical HTTP methods) */
    if (dst_port == 80 || dst_port == 8080 || src_port == 80) {
        if (parse_http_host(payload, payload_len, out_info->domain, sizeof(out_info->domain))) {
            snprintf(out_info->protocol, sizeof(out_info->protocol), "HTTP");
            out_info->has_protocol = true;
            out_info->has_domain = true;
            return true;
        }
    }

    /* Check HTTP on any port if payload starts with method */
    if (parse_http_host(payload, payload_len, out_info->domain, sizeof(out_info->domain))) {
        snprintf(out_info->protocol, sizeof(out_info->protocol), "HTTP");
        out_info->has_protocol = true;
        out_info->has_domain = true;
        return true;
    }

    /* 4. QUIC / HTTP3 (UDP 443) */
    if (ip_proto == 17 && (dst_port == 443 || src_port == 443)) {
        snprintf(out_info->protocol, sizeof(out_info->protocol), "QUIC");
        out_info->has_protocol = true;

        /* Try extracting SNI from QUIC initial handshake */
        netcap_quic_info_t qinfo;
        if (netcap_quic_inspect(payload, payload_len, &qinfo)) {
            if (qinfo.has_sni && qinfo.domain[0]) {
                strncpy(out_info->domain, qinfo.domain, sizeof(out_info->domain) - 1);
                out_info->domain[sizeof(out_info->domain) - 1] = '\0';
                out_info->has_domain = true;
            }
        }
        return true;
    }

    /* 5. Common ports fallback */
    if (dst_port == 443 || src_port == 443) {
        snprintf(out_info->protocol, sizeof(out_info->protocol), "HTTPS");
        out_info->has_protocol = true;
        return true;
    }
    if (dst_port == 22 || src_port == 22) {
        snprintf(out_info->protocol, sizeof(out_info->protocol), "SSH");
        out_info->has_protocol = true;
        return true;
    }
    if (dst_port == 853 || src_port == 853) {
        snprintf(out_info->protocol, sizeof(out_info->protocol), "DoT");
        out_info->has_protocol = true;
        return true;
    }

    return false;
}
