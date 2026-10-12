#ifndef KOTENGINE_JA4_H
#define KOTENGINE_JA4_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JA4_STRING_LEN 37 /* e.g. "t13d1516h2_8daaf6152771_0271701e699e" + \0 */

typedef struct {
    char ja4[JA4_STRING_LEN];
    bool valid;
} kotengine_ja4_t;

/**
 * Generates a JA4 fingerprint string from TLS / QUIC ClientHello attributes.
 *
 * @param is_quic True if QUIC/UDP, false if TLS/TCP
 * @param tls_version TLS version (e.g. 0x0303, 0x0304)
 * @param has_sni True if domain SNI was present
 * @param ciphers Array of 16-bit cipher suite IDs
 * @param num_ciphers Number of cipher suites
 * @param extensions Array of 16-bit extension IDs
 * @param num_extensions Number of extensions
 * @param alpn ALPN string (e.g. "h2", "http/1.1") or NULL
 * @return kotengine_ja4_t struct containing the 36-char JA4 string
 */
kotengine_ja4_t kotengine_generate_ja4(bool is_quic,
                                       uint16_t tls_version,
                                       bool has_sni,
                                       const uint16_t *ciphers,
                                       size_t num_ciphers,
                                       const uint16_t *extensions,
                                       size_t num_extensions,
                                       const char *alpn);

#ifdef __cplusplus
}
#endif

#endif /* KOTENGINE_JA4_H */
