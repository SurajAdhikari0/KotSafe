#ifndef NETCAP_PACKET_RING_H
#define NETCAP_PACKET_RING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_RING_PACKET_SIZE 2048

typedef struct {
    uint64_t ts_us;
    uint32_t len;
    uint8_t data[MAX_RING_PACKET_SIZE];
} netcap_ring_pkt_t;

typedef struct netcap_packet_ring netcap_packet_ring_t;

/* Creates a lock-free SPSC packet ring buffer. Capacity must be a power of two (e.g. 512, 1024) */
netcap_packet_ring_t *netcap_packet_ring_create(size_t capacity);
void netcap_packet_ring_destroy(netcap_packet_ring_t *ring);

/* Enqueues a packet from the Producer (TUN read thread). Lock-free.
 * Returns true on success, false if ring is full. */
bool netcap_packet_ring_push(netcap_packet_ring_t *ring, uint64_t ts_us,
                             const uint8_t *data, uint32_t len);

/* Dequeues a packet from the Consumer (Writer/Stream thread). Lock-free.
 * Returns true on success, false if ring is empty. */
bool netcap_packet_ring_pop(netcap_packet_ring_t *ring, netcap_ring_pkt_t *out_pkt);

/* Returns current number of items waiting in the ring */
size_t netcap_packet_ring_count(const netcap_packet_ring_t *ring);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_PACKET_RING_H */
