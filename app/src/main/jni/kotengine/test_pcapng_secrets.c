#define _POSIX_C_SOURCE 200809L
#include "pcapng_secrets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>

int main(void) {
    printf("--- Testing PCAPng Decryption Secrets Block (DSB) ---\n");

    const char sample_key[] = "CLIENT_RANDOM 112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00 deadbeefcafebabe\n";
    uint8_t dsb_buf[256];

    /* 1. Test build DSB */
    size_t blk_sz = netcap_pcapng_build_dsb(PCAPNG_DSB_SECRETS_TLS, (const uint8_t*)sample_key, strlen(sample_key), dsb_buf, sizeof(dsb_buf));
    assert(blk_sz > 0);

    uint32_t btype, blen, stype, slen, blen_trail;
    memcpy(&btype, dsb_buf, 4);
    memcpy(&blen, dsb_buf + 4, 4);
    memcpy(&stype, dsb_buf + 8, 4);
    memcpy(&slen, dsb_buf + 12, 4);
    memcpy(&blen_trail, dsb_buf + blk_sz - 4, 4);

    assert(btype == PCAPNG_DSB_TYPE);
    assert(stype == PCAPNG_DSB_SECRETS_TLS);
    assert(slen == strlen(sample_key));
    assert(blen == blk_sz);
    assert(blen_trail == blk_sz);
    assert((blk_sz % 4) == 0); /* 32-bit aligned */

    printf("DSB block construction: OK (total block len=%zu, aligned)\n", blk_sz);

    /* 2. Test secrets store */
    netcap_secrets_store_t *store = netcap_secrets_create(10);
    assert(store != NULL);

    assert(netcap_secrets_add_tls_key(store, sample_key) == 0);
    assert(netcap_secrets_add_tls_key(store, "SERVER_HANDSHAKE_TRAFFIC_SECRET aabbcc ddeeff\n") == 0);

    /* 3. Test dump to socket */
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    assert(netcap_secrets_dump_all_to_fd(store, sv[0]) == 0);

    uint8_t recv_buf[1024];
    ssize_t n = recv(sv[1], recv_buf, sizeof(recv_buf), 0);
    assert(n > 0);
    uint32_t first_type;
    memcpy(&first_type, recv_buf, 4);
    assert(first_type == PCAPNG_DSB_TYPE);

    close(sv[0]);
    close(sv[1]);
    netcap_secrets_destroy(store);

    printf("DSB store and stream dump: OK\n");
    printf("ALL PCAPNG SECRETS TESTS PASSED!\n");
    return 0;
}
