#include "proxy_relay.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    netcap_proxy_relay_t *pr = netcap_proxy_relay_create();
    assert(pr != NULL);

    /* 1. Add redirect rule: TCP 80 -> 127.0.0.1:8080 */
    assert(netcap_proxy_relay_add_rule(pr, 6, 80, 8080, "127.0.0.1") == 0);
    /* 2. Add redirect rule: TCP 443 -> 127.0.0.1:8443 */
    assert(netcap_proxy_relay_add_rule(pr, 6, 443, 8443, "127.0.0.1") == 0);

    uint8_t out_ip[16];
    uint16_t out_port = 0;
    uint8_t family = 0;

    /* Match port 80 with normal UID 10045 */
    bool matched = netcap_proxy_relay_match(pr, 10045, 6, 80, out_ip, &out_port, &family);
    assert(matched);
    assert(out_port == 8080);
    assert(family == 4);
    assert(out_ip[0] == 127 && out_ip[3] == 1);
    printf("Port 80 redirect: OK -> 127.0.0.1:8080\n");

    /* Match port 443 with normal UID 10045 */
    matched = netcap_proxy_relay_match(pr, 10045, 6, 443, out_ip, &out_port, &family);
    assert(matched);
    assert(out_port == 8443);
    printf("Port 443 redirect: OK -> 127.0.0.1:8443\n");

    /* Set proxy app UID 10099 as exempt */
    int32_t exempt_uids[] = {10099};
    netcap_proxy_relay_set_exempt_uids(pr, exempt_uids, 1);

    /* Flow from proxy app UID 10099 must NOT be redirected */
    matched = netcap_proxy_relay_match(pr, 10099, 6, 80, out_ip, &out_port, &family);
    assert(!matched);
    printf("Proxy exemption test: OK (UID 10099 not redirected)\n");

    /* Remove port 80 rule */
    netcap_proxy_relay_remove_rule(pr, 6, 80);
    matched = netcap_proxy_relay_match(pr, 10045, 6, 80, out_ip, &out_port, &family);
    assert(!matched);
    printf("Rule removal test: OK\n");

    netcap_proxy_relay_destroy(pr);
    printf("ALL PROXY RELAY TESTS PASSED!\n");
    return 0;
}
