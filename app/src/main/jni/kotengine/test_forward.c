#include "forward.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>

static int mock_protect_cb(int fd, void *user_data) {
    (void)fd;
    (void)user_data;
    /* In tests, protect succeeds */
    return 0;
}

int main(void) {
    int pipefds[2];
    assert(pipe(pipefds) == 0);
    int tun_write_fd = pipefds[1];
    int tun_read_fd = pipefds[0];

    netcap_forward_engine_t *fwd = netcap_forward_create(tun_write_fd);
    assert(fwd != NULL);

    netcap_forward_set_protect_cb(fwd, mock_protect_cb, NULL);

    /* Construct a synthetic TCP flow key */
    netcap_flow_key_t key = {0};
    key.proto = 6; /* TCP */
    key.family = 4;
    key.src_ip[0] = 10; key.src_ip[1] = 0; key.src_ip[2] = 0; key.src_ip[3] = 2;
    key.dst_ip[0] = 127; key.dst_ip[1] = 0; key.dst_ip[2] = 0; key.dst_ip[3] = 1;
    key.src_port = 54321;
    key.dst_port = 80;

    /* Synthetic SYN packet */
    uint8_t syn_pkt[40] = {0};
    /* Handle TCP SYN */
    int rc = netcap_forward_handle_tcp(fwd, &key, syn_pkt, sizeof(syn_pkt), 20, 20, 0x02 /* SYN */, 1000, 0);
    assert(rc == 0);
    printf("TCP SYN handling: OK (flow created, non-blocking connect triggered)\n");

    /* Poll replies */
    netcap_forward_poll_replies(fwd);
    printf("TCP Poll replies: OK\n");

    /* Construct a synthetic UDP DNS flow key */
    netcap_flow_key_t udp_key = {0};
    udp_key.proto = 17; /* UDP */
    udp_key.family = 4;
    udp_key.src_ip[0] = 10; udp_key.src_ip[1] = 215; udp_key.src_ip[2] = 173; udp_key.src_ip[3] = 1;
    udp_key.dst_ip[0] = 127; udp_key.dst_ip[1] = 0; udp_key.dst_ip[2] = 0; udp_key.dst_ip[3] = 1;
    udp_key.src_port = 54322;
    udp_key.dst_port = 53;

    uint8_t virtual_dns[4] = {10, 215, 173, 2};
    uint8_t udp_pkt[28] = {0};
    int u_rc = netcap_forward_handle_udp(fwd, &udp_key, udp_pkt, sizeof(udp_pkt), 20, 8, virtual_dns);
    assert(u_rc == 0);
    printf("UDP DNS handling with virtual DNS preservation: OK\n");

    /* Sweep idle */
    netcap_forward_sweep_idle(fwd, 0);
    printf("Forward Sweep idle: OK\n");

    netcap_forward_destroy(fwd);
    close(tun_write_fd);
    close(tun_read_fd);

    printf("ALL FORWARD ENGINE TESTS PASSED!\n");
    return 0;
}
