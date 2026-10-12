#define _POSIX_C_SOURCE 200809L
#include "pcap_stream_server.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    uint16_t port = 18080;
    netcap_stream_server_t *srv = netcap_stream_server_create(port);
    assert(srv != NULL);
    printf("PCAP Stream Server started on port %u\n", port);

    /* Connect client socket */
    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(client_sock >= 0);

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &saddr.sin_addr);

    int rc = connect(client_sock, (struct sockaddr *)&saddr, sizeof(saddr));
    assert(rc == 0);

    /* Server accepts */
    netcap_stream_server_poll(srv);
    assert(netcap_stream_server_client_count(srv) == 1);
    printf("Client connected and accepted!\n");

    /* Client receives HTTP header + SHB + IDB */
    uint8_t rx_buf[1024];
    ssize_t n = recv(client_sock, rx_buf, sizeof(rx_buf), 0);
    assert(n > 0);
    assert(strstr((char *)rx_buf, "HTTP/1.1 200 OK") != NULL);
    assert(strstr((char *)rx_buf, "application/vnd.tcpdump.pcap") != NULL);
    printf("HTTP 200 Header + SHB/IDB received: %zd bytes\n", n);

    /* Broadcast a packet */
    uint8_t dummy_pkt[64] = {0x45, 0x00, 0x00, 0x40};
    netcap_stream_server_broadcast(srv, 1000000, dummy_pkt, sizeof(dummy_pkt));

    /* Client receives EPB block */
    n = recv(client_sock, rx_buf, sizeof(rx_buf), 0);
    assert(n >= (ssize_t)(32 + sizeof(dummy_pkt)));
    /* Check EPB magic 0x00000006 */
    uint32_t block_type = *(uint32_t *)rx_buf;
    assert(block_type == 0x00000006);
    printf("EPB Packet Block received: %zd bytes (Block Type 0x%08x)\n", n, block_type);

    close(client_sock);
    netcap_stream_server_destroy(srv);
    printf("ALL STREAM SERVER TESTS PASSED!\n");
    return 0;
}
