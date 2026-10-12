#include "ja4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- Standalone Minimal SHA-256 Implementation --- */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_ctx_t;

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    uint32_t w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t left = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (left) {
        size_t fill = 64 - left;
        if (len < fill) {
            memcpy(ctx->buffer + left, p, len);
            return;
        }
        memcpy(ctx->buffer + left, p, fill);
        sha256_transform(ctx->state, ctx->buffer);
        p += fill;
        len -= fill;
    }

    while (len >= 64) {
        sha256_transform(ctx->state, p);
        p += 64;
        len -= 64;
    }

    if (len) {
        memcpy(ctx->buffer, p, len);
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]) {
    static const uint8_t pad[64] = { 0x80 };
    uint8_t count_bytes[8];
    uint64_t bits = ctx->count * 8;
    for (int i = 7; i >= 0; i--) {
        count_bytes[i] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
    }

    size_t pad_len = ((ctx->count & 0x3F) < 56) ? (56 - (ctx->count & 0x3F)) : (120 - (ctx->count & 0x3F));
    sha256_update(ctx, pad, pad_len);
    sha256_update(ctx, count_bytes, 8);

    for (int i = 0; i < 8; i++) {
        hash[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);
    }
}

/* Compare function for qsort */
static int cmp_u16(const void *a, const void *b) {
    uint16_t va = *(const uint16_t *)a;
    uint16_t vb = *(const uint16_t *)b;
    return (va > vb) - (va < vb);
}

/* Check if cipher is GREASE (RFC 8701: 0x0a0a, 0x1a1a, ... 0xfafa) */
static inline bool is_grease(uint16_t val) {
    return ((val & 0x0F0F) == 0x0A0A) && ((val >> 8) == (val & 0xFF));
}

kotengine_ja4_t kotengine_generate_ja4(bool is_quic,
                                       uint16_t tls_version,
                                       bool has_sni,
                                       const uint16_t *ciphers,
                                       size_t num_ciphers,
                                       const uint16_t *extensions,
                                       size_t num_extensions,
                                       const char *alpn) {
    kotengine_ja4_t result;
    memset(&result, 0, sizeof(result));

    /* 1. Protocol ('t' or 'q') */
    char proto = is_quic ? 'q' : 't';

    /* 2. Version (13, 12, 11, 10, 00) */
    char ver[3] = "00";
    if (tls_version == 0x0304 || tls_version == 0x7F1C) strcpy(ver, "13");
    else if (tls_version == 0x0303) strcpy(ver, "12");
    else if (tls_version == 0x0302) strcpy(ver, "11");
    else if (tls_version == 0x0301) strcpy(ver, "10");

    /* 3. SNI indicator ('d' or 'i') */
    char sni = has_sni ? 'd' : 'i';

    /* Filter out GREASE and calculate sorted ciphers */
    uint16_t clean_ciphers[256];
    size_t clean_ciphers_count = 0;
    for (size_t i = 0; i < num_ciphers && clean_ciphers_count < 256; i++) {
        if (!is_grease(ciphers[i])) {
            clean_ciphers[clean_ciphers_count++] = ciphers[i];
        }
    }
    qsort(clean_ciphers, clean_ciphers_count, sizeof(uint16_t), cmp_u16);

    /* Filter out GREASE, SNI (0x0000), and ALPN (0x0010) for extension hash */
    uint16_t clean_extensions[256];
    size_t clean_ext_count = 0;
    for (size_t i = 0; i < num_extensions && clean_ext_count < 256; i++) {
        uint16_t ext = extensions[i];
        if (!is_grease(ext) && ext != 0x0000 && ext != 0x0010) {
            clean_extensions[clean_ext_count++] = ext;
        }
    }
    qsort(clean_extensions, clean_ext_count, sizeof(uint16_t), cmp_u16);

    /* 4. Cipher count (max 99) */
    int cipher_count = (int)(clean_ciphers_count > 99 ? 99 : clean_ciphers_count);

    /* 5. Extension count (max 99) */
    int ext_count = (int)(clean_ext_count > 99 ? 99 : clean_ext_count);

    /* 6. ALPN (2 chars: first and last char of ALPN string, or "00") */
    char alpn_code[3] = "00";
    if (alpn && strlen(alpn) > 0) {
        size_t alen = strlen(alpn);
        alpn_code[0] = alpn[0];
        alpn_code[1] = alpn[alen - 1];
        alpn_code[2] = '\0';
    }

    /* Hash ciphers */
    char cipher_str[2048] = {0};
    size_t c_offset = 0;
    for (size_t i = 0; i < clean_ciphers_count; i++) {
        if (i > 0 && c_offset < sizeof(cipher_str) - 1) cipher_str[c_offset++] = ',';
        c_offset += snprintf(cipher_str + c_offset, sizeof(cipher_str) - c_offset, "%04x", clean_ciphers[i]);
    }

    uint8_t cipher_hash[32];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, cipher_str, strlen(cipher_str));
    sha256_final(&ctx, cipher_hash);

    char cipher_hash_hex[13] = {0};
    for (int i = 0; i < 6; i++) {
        sprintf(cipher_hash_hex + (i * 2), "%02x", cipher_hash[i]);
    }

    /* Hash extensions */
    char ext_str[2048] = {0};
    size_t e_offset = 0;
    for (size_t i = 0; i < clean_ext_count; i++) {
        if (i > 0 && e_offset < sizeof(ext_str) - 1) ext_str[e_offset++] = ',';
        e_offset += snprintf(ext_str + e_offset, sizeof(ext_str) - e_offset, "%04x", clean_extensions[i]);
    }

    uint8_t ext_hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, ext_str, strlen(ext_str));
    sha256_final(&ctx, ext_hash);

    char ext_hash_hex[13] = {0};
    for (int i = 0; i < 6; i++) {
        sprintf(ext_hash_hex + (i * 2), "%02x", ext_hash[i]);
    }

    /* Form JA4 string: e.g. "t13d1516h2_8daaf6152771_0271701e699e" */
    snprintf(result.ja4, sizeof(result.ja4), "%c%s%c%02d%02d%s_%s_%s",
             proto, ver, sni, cipher_count, ext_count, alpn_code,
             cipher_hash_hex, ext_hash_hex);
    result.valid = true;
    return result;
}
