#ifndef NETCAP_STREAM_SERVER_H
#define NETCAP_STREAM_SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct netcap_stream_server netcap_stream_server_t;

/*
 * Creates an embedded HTTP live PCAPng streaming server on the given port (e.g. 8080).
 * Clients connecting to http://<ip>:<port>/pcap receive live Wireshark-compatible PCAPng stream.
 */
netcap_stream_server_t *netcap_stream_server_create(uint16_t port);
void netcap_stream_server_destroy(netcap_stream_server_t *srv);

/*
 * Broadcasts a captured packet to all currently connected streaming clients.
 */
void netcap_stream_server_broadcast(netcap_stream_server_t *srv, uint64_t ts_us,
                                    const uint8_t *packet, uint32_t len);

/*
 * Polls for incoming client connections (non-blocking).
 * Call periodically or alongside capture loop iterations.
 */
void netcap_stream_server_poll(netcap_stream_server_t *srv);

/* Callback invoked when a new streaming client connects (e.g. to dump DSBs) */
typedef void (*netcap_stream_client_cb)(int client_fd, void *user_data);
void netcap_stream_server_set_client_connect_cb(netcap_stream_server_t *srv,
                                                netcap_stream_client_cb cb, void *user_data);

/* Broadcast arbitrary raw PCAPng block (such as DSB) to all connected clients */
void netcap_stream_server_broadcast_raw(netcap_stream_server_t *srv, const uint8_t *data, size_t len);

/* Returns number of actively connected streaming clients */
uint32_t netcap_stream_server_client_count(const netcap_stream_server_t *srv);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_STREAM_SERVER_H */
