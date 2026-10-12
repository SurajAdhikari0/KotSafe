#include "payload_buffer.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    netcap_payload_buf_t *pb = netcap_payload_buf_create(NETCAP_PAYLOAD_MINIMAL);
    assert(pb != NULL);

    const char req[] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";

    netcap_payload_buf_append(pb, true, (const uint8_t *)req, strlen(req), 1000);
    netcap_payload_buf_append(pb, false, (const uint8_t *)resp, strlen(resp), 1050);

    uint8_t out[1024];
    uint32_t n_tx = netcap_payload_buf_get(pb, 1, out, sizeof(out));
    assert(n_tx == strlen(req));
    assert(memcmp(out, req, n_tx) == 0);
    printf("Tx Payload dump: OK (%u bytes)\n", n_tx);

    uint32_t n_rx = netcap_payload_buf_get(pb, 2, out, sizeof(out));
    assert(n_rx == strlen(resp));
    assert(memcmp(out, resp, n_rx) == 0);
    printf("Rx Payload dump: OK (%u bytes)\n", n_rx);

    char hex_view[2048];
    uint32_t hex_len = netcap_payload_format_hex(out, n_rx, hex_view, sizeof(hex_view));
    assert(hex_len > 0);
    printf("Formatted Hex View:\n%s\n", hex_view);

    netcap_payload_buf_destroy(pb);
    printf("ALL PAYLOAD BUFFER TESTS PASSED!\n");
    return 0;
}
