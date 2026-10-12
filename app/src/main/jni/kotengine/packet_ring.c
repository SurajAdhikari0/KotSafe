#define _POSIX_C_SOURCE 200809L
#include "packet_ring.h"
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

struct netcap_packet_ring {
    netcap_ring_pkt_t *packets;
    size_t capacity;
    _Atomic size_t head;
    _Atomic size_t tail;
};

static size_t next_pow2(size_t n) {
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

netcap_packet_ring_t *netcap_packet_ring_create(size_t capacity) {
    size_t cap = next_pow2(capacity > 0 ? capacity : 512);
    netcap_packet_ring_t *ring = calloc(1, sizeof(*ring));
    if (!ring) return NULL;

    ring->packets = calloc(cap, sizeof(netcap_ring_pkt_t));
    if (!ring->packets) {
        free(ring);
        return NULL;
    }

    ring->capacity = cap;
    atomic_init(&ring->head, 0);
    atomic_init(&ring->tail, 0);
    return ring;
}

void netcap_packet_ring_destroy(netcap_packet_ring_t *ring) {
    if (!ring) return;
    free(ring->packets);
    free(ring);
}

bool netcap_packet_ring_push(netcap_packet_ring_t *ring, uint64_t ts_us,
                             const uint8_t *data, uint32_t len) {
    if (!ring || !data || len == 0) return false;

    size_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if ((head - tail) >= ring->capacity) {
        return false; /* Ring buffer is full */
    }

    size_t idx = head & (ring->capacity - 1);
    uint32_t copy_len = len < MAX_RING_PACKET_SIZE ? len : MAX_RING_PACKET_SIZE;

    ring->packets[idx].ts_us = ts_us;
    ring->packets[idx].len = copy_len;
    memcpy(ring->packets[idx].data, data, copy_len);

    atomic_store_explicit(&ring->head, head + 1, memory_order_release);
    return true;
}

bool netcap_packet_ring_pop(netcap_packet_ring_t *ring, netcap_ring_pkt_t *out_pkt) {
    if (!ring || !out_pkt) return false;

    size_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

    if (tail == head) {
        return false; /* Ring buffer is empty */
    }

    size_t idx = tail & (ring->capacity - 1);
    *out_pkt = ring->packets[idx];

    atomic_store_explicit(&ring->tail, tail + 1, memory_order_release);
    return true;
}

size_t netcap_packet_ring_count(const netcap_packet_ring_t *ring) {
    if (!ring) return 0;
    size_t head = atomic_load_explicit(&((netcap_packet_ring_t *)ring)->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&((netcap_packet_ring_t *)ring)->tail, memory_order_relaxed);
    return (head >= tail) ? (head - tail) : 0;
}
