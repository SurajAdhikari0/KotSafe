/* Host test: IPv6 TCP SYN-ACK and IPv6 UDP reply synthesis with valid checksums.
 * Build: gcc -o test_forward_v6 test_forward_v6.c forward.c conn_table.c payload_buffer.c -lm */
#include "forward.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

static uint16_t verify_l4_v6(const uint8_t *pkt, uint32_t len) {
    uint32_t l4_len = ((uint32_t)pkt[4] << 8) | pkt[5];
    if (40 + l4_len > len) return 1;
    uint32_t sum = 0;
    for (int i = 8; i < 40; i += 2) sum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    sum += l4_len >> 16; sum += l4_len & 0xFFFF; sum += pkt[6];
    const uint8_t *d = pkt + 40;
    for (uint32_t i = 0; i + 1 < l4_len; i += 2) sum += ((uint32_t)d[i] << 8) | d[i + 1];
    if (l4_len & 1) sum += (uint32_t)d[l4_len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum; /* 0 == valid */
}

static int read_pkt(int fd, uint8_t *buf, size_t cap, netcap_forward_engine_t *f) {
    for (int i = 0; i < 200; i++) {
        netcap_forward_poll_replies(f);
        ssize_t n = read(fd, buf, cap);
        if (n > 0) return (int)n;
        usleep(5000);
    }
    return -1;
}

int main(void) {
    int fails = 0;
    int pfd[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pfd) != 0) return 1;
    fcntl(pfd[0], F_SETFL, O_NONBLOCK);
    netcap_forward_engine_t *f = netcap_forward_create(pfd[1]);

    uint8_t client[16] = {0xfd,0,0,2,0xfd,0,0,1,0xfd,0,0,1,0xfd,0,0,1};
    uint8_t loop6[16] = {0}; loop6[15] = 1;
    uint8_t buf[70000];

    /* --- TCP over IPv6 --- */
    int ls = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 a = {0};
    a.sin6_family = AF_INET6; a.sin6_addr = in6addr_loopback;
    bind(ls, (struct sockaddr *)&a, sizeof(a)); listen(ls, 4);
    socklen_t al = sizeof(a); getsockname(ls, (struct sockaddr *)&a, &al);

    netcap_flow_key_t k = {0};
    k.proto = 6; k.family = 6;
    memcpy(k.src_ip, client, 16); memcpy(k.dst_ip, loop6, 16);
    k.src_port = 40000; k.dst_port = ntohs(a.sin6_port);
    uint8_t syn[60] = {0};
    netcap_forward_handle_tcp(f, &k, syn, 60, 40, 20, 0x02, 12345, 0);
    int n = read_pkt(pfd[0], buf, sizeof(buf), f);
    if (n < 60 || (buf[0] >> 4) != 6 || buf[6] != 6 || buf[40 + 13] != 0x12 || verify_l4_v6(buf, n) != 0) {
        printf("IPv6 TCP SYN-ACK: FAIL (n=%d)\n", n); fails++;
    } else printf("IPv6 TCP SYN-ACK (valid checksum): OK\n");
    close(ls);

    /* --- UDP over IPv6 --- */
    int us = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 ua = {0};
    ua.sin6_family = AF_INET6; ua.sin6_addr = in6addr_loopback;
    bind(us, (struct sockaddr *)&ua, sizeof(ua));
    socklen_t ual = sizeof(ua); getsockname(us, (struct sockaddr *)&ua, &ual);

    netcap_flow_key_t uk = k;
    uk.proto = 17; uk.src_port = 40001; uk.dst_port = ntohs(ua.sin6_port);
    uint8_t udp_pkt[40 + 8 + 5] = {0};
    memcpy(udp_pkt + 48, "hello", 5);
    netcap_forward_handle_udp(f, &uk, udp_pkt, sizeof(udp_pkt), 40, 8, NULL);

    struct sockaddr_in6 from; socklen_t fl = sizeof(from); char rb[16];
    struct pollfd up = { us, POLLIN, 0 };
    poll(&up, 1, 1000);
    ssize_t r = recvfrom(us, rb, sizeof(rb), 0, (struct sockaddr *)&from, &fl);
    if (r == 5) sendto(us, "world", 5, 0, (struct sockaddr *)&from, fl);
    n = read_pkt(pfd[0], buf, sizeof(buf), f);
    if (n != 40 + 8 + 5 || buf[6] != 17 || memcmp(buf + 48, "world", 5) != 0 ||
        (buf[46] == 0 && buf[47] == 0) || verify_l4_v6(buf, n) != 0) {
        printf("IPv6 UDP reply: FAIL (n=%d)\n", n); fails++;
    } else printf("IPv6 UDP reply (non-zero valid checksum): OK\n");
    close(us);

    netcap_forward_destroy(f);
    printf(fails ? "IPV6 FORWARD TESTS FAILED\n" : "ALL IPV6 FORWARD TESTS PASSED!\n");
    return fails ? 1 : 0;
}
