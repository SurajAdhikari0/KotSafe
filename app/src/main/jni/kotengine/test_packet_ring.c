#define _POSIX_C_SOURCE 200809L
#include "packet_ring.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#define NUM_TEST_ITEMS 50000

static void *producer_fn(void *arg) {
    netcap_packet_ring_t *ring = (netcap_packet_ring_t *)arg;
    uint8_t dummy[64];
    memset(dummy, 0xAA, sizeof(dummy));

    for (size_t i = 0; i < NUM_TEST_ITEMS; i++) {
        while (!netcap_packet_ring_push(ring, i, dummy, sizeof(dummy))) {
            /* retry if full */
        }
    }
    return NULL;
}

int main(void) {
    printf("--- Testing Lock-Free SPSC Packet Ring Buffer ---\n");

    netcap_packet_ring_t *ring = netcap_packet_ring_create(1024);
    assert(ring != NULL);

    pthread_t prod_thread;
    assert(pthread_create(&prod_thread, NULL, producer_fn, ring) == 0);

    size_t received = 0;
    netcap_ring_pkt_t pkt;

    while (received < NUM_TEST_ITEMS) {
        if (netcap_packet_ring_pop(ring, &pkt)) {
            assert(pkt.ts_us == received);
            assert(pkt.len == 64);
            received++;
        }
    }

    pthread_join(prod_thread, NULL);
    assert(received == NUM_TEST_ITEMS);
    assert(netcap_packet_ring_count(ring) == 0);

    printf("Lock-free concurrent SPSC: OK (%zu items passed across threads)\n", received);
    netcap_packet_ring_destroy(ring);

    printf("ALL PACKET RING TESTS PASSED!\n");
    return 0;
}
