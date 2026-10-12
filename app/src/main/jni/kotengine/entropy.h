#ifndef KOTENGINE_ENTROPY_H
#define KOTENGINE_ENTROPY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ENTROPY_SUSPICIOUS_THRESHOLD 7.50f
#define ENTROPY_ENCRYPTED_THRESHOLD  7.80f

typedef struct {
    float entropy;            /* 0.0 to 8.0 bits per byte */
    bool is_encrypted;        /* True if entropy >= 7.80 */
    bool is_suspicious;       /* True if unexpected high entropy for plaintext protocol */
    uint32_t byte_count;      /* Total bytes analyzed */
} kotengine_entropy_result_t;

/**
 * Calculates Shannon entropy of a byte buffer in bits per byte (0.00 to 8.00).
 */
float kotengine_calculate_entropy(const uint8_t *data, size_t len);

/**
 * Analyzes a payload buffer for exfiltration / encryption characteristics.
 */
kotengine_entropy_result_t kotengine_analyze_entropy(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KOTENGINE_ENTROPY_H */
