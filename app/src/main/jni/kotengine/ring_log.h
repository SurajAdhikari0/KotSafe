#ifndef NETCAP_RING_LOG_H
#define NETCAP_RING_LOG_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ring_log: single-producer/single-consumer ring buffer of fixed-size
 * log records. The capture thread (producer) writes records without
 * ever blocking on the JNI/UI-reporting thread (consumer); if the
 * consumer falls behind, the oldest unread record is overwritten and
 * a drop counter increments rather than stalling the packet loop.
 *
 * This matters because the capture loop is latency-sensitive (packets
 * are still arriving from the TUN fd) while JNI upcalls into Java can
 * stall arbitrarily long (GC pauses, UI thread contention).
 */

#define NETCAP_LOG_MSG_MAX 160

typedef struct {
    uint64_t timestamp_ms;
    uint8_t  level; /* 0=debug 1=info 2=warn 3=error */
    char     msg[NETCAP_LOG_MSG_MAX];
} netcap_log_rec_t;

typedef struct {
    netcap_log_rec_t *buf;
    uint32_t capacity;       /* power of two */
    uint32_t mask;
    _Atomic uint32_t head;   /* next write index (producer-owned) */
    _Atomic uint32_t tail;   /* next read index (consumer-owned) */
    _Atomic uint64_t dropped;
} netcap_ring_log_t;

/* capacity_pow2 must be a power of two (e.g. 1024). */
int netcap_ring_log_init(netcap_ring_log_t *r, uint32_t capacity_pow2);
void netcap_ring_log_destroy(netcap_ring_log_t *r);

/* Producer side - never blocks, never fails (overwrites oldest on overflow). */
void netcap_ring_log_push(netcap_ring_log_t *r, uint8_t level, const char *msg);

/* Consumer side - pops up to `max_out` records into `out`, returns count
 * actually popped (0 if empty). Call periodically from the reporting
 * thread and forward to Java in a single batched JNI upcall. */
uint32_t netcap_ring_log_drain(netcap_ring_log_t *r, netcap_log_rec_t *out, uint32_t max_out);

uint64_t netcap_ring_log_dropped_count(const netcap_ring_log_t *r);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_RING_LOG_H */
