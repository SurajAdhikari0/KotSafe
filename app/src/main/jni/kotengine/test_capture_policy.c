#define _POSIX_C_SOURCE 200809L
#include "capture_engine.h"
#include "forward.h"
#include <assert.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int32_t resolve_uid(uint8_t proto, const char *src, uint16_t sport,
    const char *dst, uint16_t dport, void *unused) {
    (void)proto; (void)src; (void)dst; (void)dport; (void)unused;
    return sport == 19999 ? -1 : sport;
}
static int readable(int fd, int ms) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return poll(&p, 1, ms) > 0;
}
static void send_udp(int fd, uint16_t sport, uint16_t dport) {
    uint8_t packet[32] = {0};
    packet[0] = 0x45; packet[3] = sizeof(packet); packet[8] = 64; packet[9] = 17;
    assert(inet_pton(AF_INET, "10.0.0.2", packet + 12) == 1);
    assert(inet_pton(AF_INET, "127.0.0.1", packet + 16) == 1);
    packet[20] = sport >> 8; packet[21] = sport;
    packet[22] = dport >> 8; packet[23] = dport;
    packet[25] = 12;
    memcpy(packet + 28, "test", 4);
    assert(send(fd, packet, sizeof(packet), 0) == sizeof(packet));
}
static void send_syn(int fd, uint16_t sport, uint16_t dport) {
    uint8_t packet[40] = {0};
    packet[0] = 0x45; packet[3] = sizeof(packet); packet[8] = 64; packet[9] = 6;
    assert(inet_pton(AF_INET, "10.0.0.2", packet + 12) == 1);
    assert(inet_pton(AF_INET, "127.0.0.1", packet + 16) == 1);
    packet[20] = sport >> 8; packet[21] = sport;
    packet[22] = dport >> 8; packet[23] = dport;
    packet[27] = 100; packet[32] = 0x50; packet[33] = 2;
    packet[34] = 0xff; packet[35] = 0xff;
    assert(send(fd, packet, sizeof(packet), 0) == sizeof(packet));
}
static void await_block_count(netcap_engine_t *engine, uint64_t count) {
    for (int i = 0; i < 2000; i++) {
        netcap_engine_stats_t stats;
        netcap_engine_get_stats(engine, &stats);
        if (stats.blocked_pkts >= count) return;
        struct timespec pause = {.tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
    assert(!"packet was not denied by capture loop");
}
int main(void) {
    int tun[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, tun) == 0);
    int receiver = socket(AF_INET, SOCK_DGRAM, 0);
    assert(receiver >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(receiver, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t address_len = sizeof(address);
    assert(getsockname(receiver, (struct sockaddr *)&address, &address_len) == 0);
    uint16_t port = ntohs(address.sin_port);
    netcap_engine_config_t config = {.max_connections = 64, .idle_timeout_secs = 120, .log_ring_capacity = 64};
    netcap_engine_t *engine = netcap_engine_create(&config);
    assert(engine);
    netcap_forward_engine_t *forward = netcap_forward_create(tun[0]);
    assert(forward);
    netcap_engine_attach_forward(engine, forward);
    netcap_engine_set_uid_resolver(engine, resolve_uid, NULL);
    int32_t allowed[] = {10001};
    assert(netcap_engine_replace_policy(engine, NETCAP_POLICY_ALLOW, true, allowed, 1, NULL, 0, NULL, 0));
    assert(netcap_engine_start(engine, tun[0], NULL, NULL) == 0);

    send_udp(tun[1], 10002, port);
    await_block_count(engine, 1);
    assert(!readable(receiver, 100));
    send_udp(tun[1], 19999, port);
    await_block_count(engine, 2);
    assert(!readable(receiver, 100));
    send_udp(tun[1], 10001, port);
    assert(readable(receiver, 2000));
    char payload[16];
    struct sockaddr_in backing;
    socklen_t backing_len = sizeof(backing);
    assert(recvfrom(receiver, payload, sizeof(payload), 0, (struct sockaddr *)&backing, &backing_len) == 4);
    puts("Real UDP receiver: selected UID passes; unselected/unknown UIDs never arrive: OK");

    const char *feed[] = {"127.0.0.1/32"};
    assert(netcap_engine_replace_policy(engine, NETCAP_POLICY_FEED, true, NULL, 0, NULL, 0, feed, 1));
    assert(netcap_engine_replace_policy(engine, NETCAP_POLICY_DENY, true, NULL, 0, NULL, 0, NULL, 0));
    send_udp(tun[1], 10001, port);
    await_block_count(engine, 3);
    assert(!readable(receiver, 100));
    puts("Feed block survives user-rule replacement in actual packet path: OK");

    assert(netcap_engine_replace_policy(engine, NETCAP_POLICY_FEED, false, NULL, 0, NULL, 0, NULL, 0));
    send_udp(tun[1], 10001, port);
    assert(readable(receiver, 2000));
    backing_len = sizeof(backing);
    assert(recvfrom(receiver, payload, sizeof(payload), 0, (struct sockaddr *)&backing, &backing_len) == 4);
    // This flow was established before allowlist changes. Delayed upstream data must not leak back.
    assert(netcap_engine_replace_policy(engine, NETCAP_POLICY_ALLOW, true, NULL, 0, NULL, 0, NULL, 0));
    assert(sendto(receiver, "reply", 5, 0, (struct sockaddr *)&backing, backing_len) == 5);
    assert(!readable(tun[1], 200));
    puts("Existing UDP flow stops returning data after allowlist revocation: OK");

    assert(netcap_engine_replace_policy(engine, NETCAP_POLICY_ALLOW, false, NULL, 0, NULL, 0, NULL, 0));
    send_udp(tun[1], 10002, port);
    assert(readable(receiver, 2000));
    assert(recv(receiver, payload, sizeof(payload), 0) == 4);
    puts("Turning off allowlist mode restores ordinary traffic: OK");
    int stream_receiver = socket(AF_INET, SOCK_STREAM, 0);
    assert(stream_receiver >= 0);
    address.sin_port = 0;
    assert(bind(stream_receiver, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(stream_receiver, 4) == 0);
    address_len = sizeof(address);
    assert(getsockname(stream_receiver, (struct sockaddr *)&address, &address_len) == 0);
    port = ntohs(address.sin_port);
    assert(netcap_engine_replace_policy(engine, NETCAP_POLICY_ALLOW, true, allowed, 1, NULL, 0, NULL, 0));
    send_syn(tun[1], 10002, port);
    await_block_count(engine, 4);
    assert(!readable(stream_receiver, 100));
    send_syn(tun[1], 10001, port);
    assert(readable(stream_receiver, 2000));
    int accepted = accept(stream_receiver, NULL, NULL);
    assert(accepted >= 0);
    assert(netcap_engine_replace_policy(engine, NETCAP_POLICY_ALLOW, true, NULL, 0, NULL, 0, NULL, 0));
    assert(readable(accepted, 2000));
    assert(recv(accepted, payload, sizeof(payload), 0) == 0);
    puts("Real TCP receiver: denied SYN never arrives; existing connection closes on revocation: OK");
    close(accepted); close(stream_receiver);

    netcap_engine_stop(engine);
    netcap_forward_destroy(forward);
    netcap_engine_destroy(engine);
    close(receiver); close(tun[0]); close(tun[1]);
    return 0;
}
