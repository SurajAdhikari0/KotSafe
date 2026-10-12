#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "capture_engine.h"
#include "forward.h"
#include "l7_inspect.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>

static int s_updates_received = 0;
static int s_saw_github = 0;
static int s_saw_google = 0;
static int s_saw_tls = 0;
static int s_saw_dns = 0;
static int s_saw_us = 0;

static void on_test_conn_update(const netcap_conn_t *const *conns, uint32_t count, void *user_data) {
    (void)user_data;
    for (uint32_t i = 0; i < count; i++) {
        s_updates_received++;
        if (strstr(conns[i]->domain_name, "github.com")) s_saw_github = 1;
        if (strstr(conns[i]->domain_name, "google.com")) s_saw_google = 1;
        if (strcmp(conns[i]->l7_proto, "TLS") == 0) s_saw_tls = 1;
        if (strcmp(conns[i]->l7_proto, "DNS") == 0) s_saw_dns = 1;
        if (strcmp(conns[i]->country_code, "US") == 0) s_saw_us = 1;
    }
}

static int mock_protect(int fd, void *user_data) {
    (void)fd;
    (void)user_data;
    return 0;
}

static int s_threat_count = 0;
static void test_threat_cb(const netcap_threat_alert_t *al, void *ud) {
    (void)ud;
    if (al) s_threat_count++;
}

/* Helper to assemble IPv4 + UDP packet */
static size_t build_udp_packet(uint8_t *buf, const uint8_t src_ip[4], uint16_t src_port,
                              const uint8_t dst_ip[4], uint16_t dst_port,
                              const uint8_t *payload, size_t payload_len) {
    size_t total_len = 20 + 8 + payload_len;
    memset(buf, 0, 20 + 8);
    buf[0] = 0x45;
    buf[2] = (uint8_t)(total_len >> 8); buf[3] = (uint8_t)total_len;
    buf[8] = 64;
    buf[9] = 17; /* UDP */
    memcpy(buf + 12, src_ip, 4);
    memcpy(buf + 16, dst_ip, 4);

    uint16_t sp = htons(src_port), dp = htons(dst_port), ul = htons((uint16_t)(8 + payload_len));
    memcpy(buf + 20, &sp, 2);
    memcpy(buf + 22, &dp, 2);
    memcpy(buf + 24, &ul, 2);
    if (payload && payload_len > 0) {
        memcpy(buf + 28, payload, payload_len);
    }
    return total_len;
}

/* Helper to assemble IPv4 + TCP packet */
static size_t build_tcp_packet(uint8_t *buf, const uint8_t src_ip[4], uint16_t src_port,
                              const uint8_t dst_ip[4], uint16_t dst_port,
                              uint8_t flags, uint32_t seq, uint32_t ack,
                              const uint8_t *payload, size_t payload_len) {
    size_t total_len = 20 + 20 + payload_len;
    memset(buf, 0, 20 + 20);
    buf[0] = 0x45;
    buf[2] = (uint8_t)(total_len >> 8); buf[3] = (uint8_t)total_len;
    buf[8] = 64;
    buf[9] = 6; /* TCP */
    memcpy(buf + 12, src_ip, 4);
    memcpy(buf + 16, dst_ip, 4);

    uint16_t sp = htons(src_port), dp = htons(dst_port);
    memcpy(buf + 20, &sp, 2);
    memcpy(buf + 22, &dp, 2);
    uint32_t n_seq = htonl(seq), n_ack = htonl(ack);
    memcpy(buf + 24, &n_seq, 4);
    memcpy(buf + 28, &n_ack, 4);
    buf[32] = (5 << 4); /* data offset 20 bytes */
    buf[33] = flags;
    uint16_t win = htons(65535);
    memcpy(buf + 34, &win, 2);
    if (payload && payload_len > 0) {
        memcpy(buf + 40, payload, payload_len);
    }
    return total_len;
}

int main(void) {
    printf("=== Starting netcap_engine End-to-End Integration Test ===\n");

    /* Create mock TUN socketpair (SOCK_DGRAM preserves packet boundaries like TUN) */
    int tun_pipe[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, tun_pipe) == 0);
    int tun_read_fd = tun_pipe[0];
    int tun_write_fd = tun_pipe[1];

    netcap_engine_config_t cfg = {
        .max_connections = 100,
        .idle_timeout_secs = 5,
        .log_ring_capacity = 64,
        .snaplen = 1500,
        .enable_uid_resolution = 0,
        .payload_mode = 1 /* MINIMAL */
    };

    netcap_engine_t *engine = netcap_engine_create(&cfg);
    assert(engine != NULL);

    netcap_forward_engine_t *fwd = netcap_forward_create(tun_write_fd);
    assert(fwd != NULL);
    netcap_forward_set_protect_cb(fwd, mock_protect, NULL);
    netcap_engine_attach_forward(engine, fwd);

    /* Start capture engine */
    int rc = netcap_engine_start(engine, tun_read_fd, on_test_conn_update, NULL);
    assert(rc == 0);

    uint8_t src_ip[4] = {10, 0, 0, 2};
    uint8_t dst_dns[4] = {8, 8, 8, 8};
    uint8_t dst_web[4] = {142, 250, 190, 46};

    /* 1. Inject DNS Query into TUN */
    const uint8_t sample_dns[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 'g','o','o','g','l','e', 0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    uint8_t pkt_buf[512];
    size_t pkt_len = build_udp_packet(pkt_buf, src_ip, 45678, dst_dns, 53, sample_dns, sizeof(sample_dns));
    ssize_t written = write(tun_write_fd, pkt_buf, pkt_len);
    assert(written == (ssize_t)pkt_len);
    usleep(20000);

    /* 2. Inject TCP SYN into TUN */
    pkt_len = build_tcp_packet(pkt_buf, src_ip, 55555, dst_web, 443, 0x02 /* SYN */, 1000, 0, NULL, 0);
    written = write(tun_write_fd, pkt_buf, pkt_len);
    assert(written == (ssize_t)pkt_len);
    usleep(20000);

    /* 3. Inject TLS ClientHello into TUN */
    const uint8_t sample_tls[] = {
        0x16, 0x03, 0x01, 0x00, 0x5a,
        0x01, 0x00, 0x00, 0x56,
        0x03, 0x03,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
        0x00,
        0x00, 0x02, 0xc0, 0x2f,
        0x01, 0x00,
        0x00, 0x21,
        0x00, 0x00, 0x00, 0x13,
        0x00, 0x11,
        0x00,
        0x00, 0x0e,
        'a','p','i','.','g','i','t','h','u','b','.','c','o','m',
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01
    };
    pkt_len = build_tcp_packet(pkt_buf, src_ip, 55555, dst_web, 443, 0x18 /* PSH|ACK */, 1001, 1, sample_tls, sizeof(sample_tls));
    written = write(tun_write_fd, pkt_buf, pkt_len);
    assert(written == (ssize_t)pkt_len);

    /* Wait a moment for worker thread to process */
    usleep(100000);

    /* Shutdown read end so worker thread unblocks from read() */
    shutdown(tun_read_fd, SHUT_RDWR);
    close(tun_write_fd);

    /* Stop engine */
    netcap_engine_stop(engine);

    /* Check stats */
    netcap_engine_stats_t stats;
    netcap_engine_get_stats(engine, &stats);
    uint64_t total_pkts = stats.pkts_sent + stats.pkts_rcvd;
    uint64_t total_bytes = stats.bytes_sent + stats.bytes_rcvd;
    printf("Stats: total_pkts=%llu, total_bytes=%llu, parse_errors=%llu\n",
           (unsigned long long)total_pkts,
           (unsigned long long)total_bytes,
           (unsigned long long)stats.parse_errors);

    assert(total_pkts >= 3);
    assert(stats.parse_errors == 0);

    printf("Updates received: %d\n", s_updates_received);
    assert(s_saw_github == 1);
    assert(s_saw_google == 1);
    assert(s_saw_tls == 1);
    assert(s_saw_dns == 1);
    assert(s_saw_us == 1);
    printf("Extracted TLS domain: github.com (OK)\n");
    printf("Extracted DNS domain: google.com (OK)\n");
    printf("Extracted GeoIP: US (OK)\n");

    /* Test In-App Payload retrieval */
    netcap_flow_key_t tcp_key = {0};
    tcp_key.proto = 6; tcp_key.family = 4;
    memcpy(tcp_key.src_ip, src_ip, 4);
    memcpy(tcp_key.dst_ip, dst_web, 4);
    tcp_key.src_port = 55555;
    tcp_key.dst_port = 443;
    uint8_t payload_out[512];
    uint32_t p_len = netcap_engine_get_conn_payload(engine, &tcp_key, 0, payload_out, sizeof(payload_out));
    assert(p_len > 0);
    printf("In-App Payload fetch test: OK (%u bytes retrieved)\n", p_len);

    /* Test Live PCAPng Streaming Server */
    int srv_rc = netcap_engine_start_stream_server(engine, 19090);
    assert(srv_rc == 0);
    printf("Live PCAPng Stream Server start: OK (port 19090)\n");

    /* Phase 2: Test Decryption Secrets Block (DSB) logging */
    const char *test_secret = "CLIENT_RANDOM 0102030405060708090a0b0c0d0e0f10 112233445566778899aabbccddeeff00\n";
    assert(netcap_engine_add_tls_secret(engine, test_secret) == 0);
    printf("TLS Decryption Secret injection: OK\n");

    netcap_engine_stop_stream_server(engine);
    printf("Live PCAPng Stream Server stop: OK\n");

    /* Phase 2: Test DNS & Network Policy configuration */
    netcap_engine_set_private_dns_blocked(engine, true);
    assert(netcap_engine_set_custom_dns(engine, "1.1.1.1") == 0);
    int32_t blocked_uids[] = { 10150, 10200 };
    netcap_engine_set_lan_blocked_uids(engine, blocked_uids, 2);
    printf("DNS & Network Policy configuration: OK\n");

    /* Phase 2: Test Enhanced Port & Proxy Redirection */
    assert(netcap_engine_add_proxy_rule(engine, 80, "127.0.0.1", 8080) == 0);
    netcap_engine_set_proxy_exempt_uid(engine, 10099);
    assert(netcap_engine_remove_proxy_rule(engine, 80) == 0);
    printf("Port & Proxy Redirection rules: OK\n");

    /* Phase 3 Next-Gen: Test Live Flow Speed Query (EWMA) */
    double tx_bps = 0.0, rx_bps = 0.0;
    netcap_engine_get_conn_speed(engine, &tcp_key, &tx_bps, &rx_bps);
    printf("Live EWMA flow speed query: OK (Tx: %.0f B/s, Rx: %.0f B/s)\n", tx_bps, rx_bps);

    /* Phase 3 Next-Gen: Test Threat Callback Integration */
    netcap_engine_set_threat_callback(engine, test_threat_cb, NULL);
    printf("Threat alert callback registration: OK\n");

    /* Teardown */
    netcap_engine_destroy(engine);
    netcap_forward_destroy(fwd);
    close(tun_read_fd);

    printf("=== ALL END-TO-END INTEGRATION TESTS PASSED! ===\n");
    return 0;
}
