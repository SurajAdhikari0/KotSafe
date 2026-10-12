#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "entropy.h"
#include "ja4.h"

int main() {
    printf("=== Testing KotEngine Shannon Entropy & JA4 Fingerprinting ===\n");

    /* 1. Test Entropy */
    uint8_t zero_buf[64] = {0};
    float zero_entropy = kotengine_calculate_entropy(zero_buf, sizeof(zero_buf));
    printf("Zero buffer entropy: %.4f (expected 0.0000)\n", zero_entropy);
    assert(zero_entropy == 0.0f);

    /* High entropy buffer (simulated encrypted payload) */
    uint8_t rand_buf[256];
    for (int i = 0; i < 256; i++) rand_buf[i] = (uint8_t)i;
    float max_entropy = kotengine_calculate_entropy(rand_buf, sizeof(rand_buf));
    printf("Uniform byte distribution entropy: %.4f (expected 8.0000)\n", max_entropy);
    assert(max_entropy > 7.99f);

    kotengine_entropy_result_t res = kotengine_analyze_entropy(rand_buf, sizeof(rand_buf));
    assert(res.is_encrypted == true);
    printf("Entropy analysis: is_encrypted=%d, is_suspicious=%d (OK)\n", res.is_encrypted, res.is_suspicious);

    /* 2. Test JA4 Fingerprint */
    uint16_t sample_ciphers[] = { 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f };
    uint16_t sample_extensions[] = { 0x0000, 0x002b, 0x000d, 0x0033, 0x0010 }; // includes SNI (0x0000) and ALPN (0x0010)

    kotengine_ja4_t ja4 = kotengine_generate_ja4(false, 0x0304, true,
                                                sample_ciphers, 5,
                                                sample_extensions, 5,
                                                "h2");
    printf("Generated JA4 Fingerprint: %s\n", ja4.ja4);
    assert(ja4.valid == true);
    assert(ja4.ja4[0] == 't'); // TCP
    assert(ja4.ja4[1] == '1' && ja4.ja4[2] == '3'); // TLS 1.3
    assert(ja4.ja4[3] == 'd'); // Domain SNI
    assert(ja4.ja4[8] == 'h' && ja4.ja4[9] == '2'); // ALPN h2

    printf("=== ALL JA4 & ENTROPY TESTS PASSED! ===\n");
    return 0;
}
