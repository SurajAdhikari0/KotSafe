#define _POSIX_C_SOURCE 200809L
#include "pcap_stream_server.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

#define MAX_STREAM_CLIENTS 8
#define LINKTYPE_RAW 101u
#define PCAPNG_SHB_TYPE 0x0A0D0D0Au
#define PCAPNG_IDB_TYPE 0x00000001u
#define PCAPNG_EPB_TYPE 0x00000006u
#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4Du

struct netcap_stream_server {
    int listen_fd;
    uint16_t port;
    int client_fds[MAX_STREAM_CLIENTS];
    uint32_t num_clients;
    netcap_stream_client_cb on_client_connect;
    void *cb_user_data;
};

static uint32_t pad32(uint32_t len) { return (len + 3) & ~3u; }

static void write_headers_to_client(int sock) {
    const char http_resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Server: netcap_stream_server\r\n"
        "Content-Type: application/vnd.tcpdump.pcap\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n";
    send(sock, http_resp, strlen(http_resp), 0);

    /* 1. Section Header Block (28 bytes) */
    uint8_t shb[28];
    uint32_t block_len = 28;
    uint32_t magic = PCAPNG_BYTE_ORDER_MAGIC;
    uint16_t major = 1, minor = 0;
    int64_t sec_len = -1;

    memcpy(shb, &(uint32_t){PCAPNG_SHB_TYPE}, 4);
    memcpy(shb + 4, &block_len, 4);
    memcpy(shb + 8, &magic, 4);
    memcpy(shb + 12, &major, 2);
    memcpy(shb + 14, &minor, 2);
    memcpy(shb + 16, &sec_len, 8);
    memcpy(shb + 24, &block_len, 4);
    send(sock, shb, sizeof(shb), 0);

    /* 2. Interface Description Block (20 bytes, no options, LINKTYPE_RAW) */
    uint8_t idb[20];
    uint32_t idb_len = 20;
    uint16_t link_type = LINKTYPE_RAW;
    uint16_t reserved = 0;
    uint32_t snaplen = 65535;

    memcpy(idb, &(uint32_t){PCAPNG_IDB_TYPE}, 4);
    memcpy(idb + 4, &idb_len, 4);
    memcpy(idb + 8, &link_type, 2);
    memcpy(idb + 10, &reserved, 2);
    memcpy(idb + 12, &snaplen, 4);
    memcpy(idb + 16, &idb_len, 4);
    send(sock, idb, sizeof(idb), 0);
}

netcap_stream_server_t *netcap_stream_server_create(uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return NULL;
    }

    if (listen(sock, 4) != 0) {
        close(sock);
        return NULL;
    }

    netcap_stream_server_t *s = calloc(1, sizeof(*s));
    if (!s) { close(sock); return NULL; }
    s->listen_fd = sock;
    s->port = port;
    for (int i = 0; i < MAX_STREAM_CLIENTS; i++) s->client_fds[i] = -1;
    return s;
}

void netcap_stream_server_destroy(netcap_stream_server_t *srv) {
    if (!srv) return;
    if (srv->listen_fd >= 0) close(srv->listen_fd);
    for (int i = 0; i < MAX_STREAM_CLIENTS; i++) {
        if (srv->client_fds[i] >= 0) close(srv->client_fds[i]);
    }
    free(srv);
}

void netcap_stream_server_poll(netcap_stream_server_t *srv) {
    if (!srv || srv->listen_fd < 0) return;

    /* Check for new client connections */
    for (;;) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int client = accept(srv->listen_fd, (struct sockaddr *)&caddr, &clen);
        if (client < 0) break;

        fcntl(client, F_SETFL, O_NONBLOCK);

        /* Find slot */
        int slot = -1;
        for (int i = 0; i < MAX_STREAM_CLIENTS; i++) {
            if (srv->client_fds[i] < 0) { slot = i; break; }
        }

        if (slot >= 0) {
            write_headers_to_client(client);
            if (srv->on_client_connect) {
                srv->on_client_connect(client, srv->cb_user_data);
            }
            srv->client_fds[slot] = client;
            srv->num_clients++;
        } else {
            close(client);
        }
    }
}

void netcap_stream_server_set_client_connect_cb(netcap_stream_server_t *srv,
                                                netcap_stream_client_cb cb, void *user_data) {
    if (!srv) return;
    srv->on_client_connect = cb;
    srv->cb_user_data = user_data;
}

void netcap_stream_server_broadcast_raw(netcap_stream_server_t *srv, const uint8_t *data, size_t len) {
    if (!srv || srv->num_clients == 0 || !data || len == 0) return;

    for (int i = 0; i < MAX_STREAM_CLIENTS; i++) {
        if (srv->client_fds[i] >= 0) {
            ssize_t sent = send(srv->client_fds[i], data, len, MSG_NOSIGNAL);
            if (sent < 0 && (errno == EPIPE || errno == ECONNRESET)) {
                close(srv->client_fds[i]);
                srv->client_fds[i] = -1;
                srv->num_clients--;
            }
        }
    }
}

void netcap_stream_server_broadcast(netcap_stream_server_t *srv, uint64_t ts_us,
                                    const uint8_t *packet, uint32_t len) {
    if (!srv || srv->num_clients == 0 || !packet || len == 0) return;

    /* Construct Enhanced Packet Block */
    uint32_t padded = pad32(len);
    uint32_t block_len = 32 + padded;
    uint8_t epb[32 + 65536];
    if (block_len > sizeof(epb)) return;

    uint32_t epb_type = PCAPNG_EPB_TYPE;
    uint32_t if_id = 0;
    uint32_t ts_hi = (uint32_t)(ts_us >> 32);
    uint32_t ts_lo = (uint32_t)(ts_us & 0xFFFFFFFFu);

    memcpy(epb, &epb_type, 4);
    memcpy(epb + 4, &block_len, 4);
    memcpy(epb + 8, &if_id, 4);
    memcpy(epb + 12, &ts_hi, 4);
    memcpy(epb + 16, &ts_lo, 4);
    memcpy(epb + 20, &len, 4);
    memcpy(epb + 24, &len, 4);
    memcpy(epb + 28, packet, len);
    if (padded > len) {
        memset(epb + 28 + len, 0, padded - len);
    }
    memcpy(epb + block_len - 4, &block_len, 4);

    for (int i = 0; i < MAX_STREAM_CLIENTS; i++) {
        if (srv->client_fds[i] >= 0) {
            ssize_t sent = send(srv->client_fds[i], epb, block_len, MSG_NOSIGNAL);
            if (sent < 0 && (errno == EPIPE || errno == ECONNRESET)) {
                close(srv->client_fds[i]);
                srv->client_fds[i] = -1;
                srv->num_clients--;
            }
        }
    }
}

uint32_t netcap_stream_server_client_count(const netcap_stream_server_t *srv) {
    return srv ? srv->num_clients : 0;
}
