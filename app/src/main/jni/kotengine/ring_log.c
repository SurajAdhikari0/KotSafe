#define _POSIX_C_SOURCE 200809L
#include "ring_log.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

int netcap_ring_log_init(netcap_ring_log_t *r, uint32_t capacity_pow2) {
    if (capacity_pow2 == 0 || (capacity_pow2 & (capacity_pow2 - 1)) != 0)
        return -1; /* must be a power of two */

    r->buf = calloc(capacity_pow2, sizeof(netcap_log_rec_t));
    if (!r->buf) return -1;

    r->capacity = capacity_pow2;
    r->mask = capacity_pow2 - 1;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
    atomic_store(&r->dropped, 0);
    return 0;
}

void netcap_ring_log_destroy(netcap_ring_log_t *r) {
    free(r->buf);
    r->buf = NULL;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void netcap_ring_log_push(netcap_ring_log_t *r, uint8_t level, const char *msg) {
    uint32_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);

    /* Buffer full: the slot we're about to write still holds an unread
     * record. Advance tail past it (drop the oldest) so the write is
     * always allowed - producer never blocks. */
    if (head - tail >= r->capacity) {
        atomic_fetch_add_explicit(&r->tail, 1, memory_order_release);
        atomic_fetch_add_explicit(&r->dropped, 1, memory_order_relaxed);
    }

    netcap_log_rec_t *slot = &r->buf[head & r->mask];
    slot->timestamp_ms = now_ms();
    slot->level = level;
    strncpy(slot->msg, msg, NETCAP_LOG_MSG_MAX - 1);
    slot->msg[NETCAP_LOG_MSG_MAX - 1] = '\0';

    atomic_store_explicit(&r->head, head + 1, memory_order_release);
}

uint32_t netcap_ring_log_drain(netcap_ring_log_t *r, netcap_log_rec_t *out, uint32_t max_out) {
    uint32_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint32_t head = atomic_load_explicit(&r->head, memory_order_acquire);

    uint32_t available = head - tail;
    uint32_t n = available < max_out ? available : max_out;

    for (uint32_t i = 0; i < n; i++) {
        out[i] = r->buf[(tail + i) & r->mask];
    }

    atomic_store_explicit(&r->tail, tail + n, memory_order_release);
    return n;
}

uint64_t netcap_ring_log_dropped_count(const netcap_ring_log_t *r) {
    return atomic_load_explicit(&r->dropped, memory_order_relaxed);
}
