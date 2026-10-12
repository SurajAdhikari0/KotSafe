#include "entropy.h"
#include <math.h>
#include <string.h>

float kotengine_calculate_entropy(const uint8_t *data, size_t len) {
    if (!data || len == 0) {
        return 0.0f;
    }

    uint32_t counts[256];
    memset(counts, 0, sizeof(counts));

    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    double inv_len = 1.0 / (double)len;

    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] * inv_len;
            entropy -= p * log2(p);
        }
    }

    return (float)entropy;
}

kotengine_entropy_result_t kotengine_analyze_entropy(const uint8_t *data, size_t len) {
    kotengine_entropy_result_t res;
    res.byte_count = (uint32_t)len;
    res.entropy = kotengine_calculate_entropy(data, len);
    res.is_encrypted = (res.entropy >= ENTROPY_ENCRYPTED_THRESHOLD && len >= 64);
    res.is_suspicious = (res.entropy >= ENTROPY_SUSPICIOUS_THRESHOLD && len >= 32);
    return res;
}
