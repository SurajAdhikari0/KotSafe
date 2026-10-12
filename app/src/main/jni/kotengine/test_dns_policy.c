#include "dns_policy.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    netcap_dns_policy_t *pol = netcap_dns_policy_create();
    assert(pol != NULL);

    /* 1. Test Block DoT */
    assert(!netcap_dns_policy_is_dot_blocked(pol));
    netcap_dns_policy_set_block_dot(pol, true);
    assert(netcap_dns_policy_is_dot_blocked(pol));
    printf("Block DoT test: OK\n");

    /* 2. Test Custom DNS */
    uint8_t dns_ip[16];
    uint8_t family = 0;
    assert(!netcap_dns_policy_get_custom_dns(pol, dns_ip, &family));

    assert(netcap_dns_policy_set_custom_dns(pol, "1.1.1.1") == 0);
    assert(netcap_dns_policy_get_custom_dns(pol, dns_ip, &family));
    assert(family == 4);
    assert(dns_ip[0] == 1 && dns_ip[1] == 1 && dns_ip[2] == 1 && dns_ip[3] == 1);
    printf("Custom DNS test: OK (1.1.1.1)\n");

    /* 3. Test LAN blocked UIDs */
    int32_t blocked_uids[] = {10042, 10088, 10123};
    netcap_dns_policy_set_lan_blocked_uids(pol, blocked_uids, 3);

    uint8_t lan_ip[4] = {192, 168, 1, 50};
    uint8_t wan_ip[4] = {8, 8, 8, 8};

    /* UID 10088 on LAN IP -> blocked */
    assert(netcap_dns_policy_is_lan_blocked(pol, 10088, lan_ip, 4));
    /* UID 10088 on WAN IP -> NOT blocked */
    assert(!netcap_dns_policy_is_lan_blocked(pol, 10088, wan_ip, 4));
    /* UID 10001 (not in blocked list) on LAN IP -> NOT blocked */
    assert(!netcap_dns_policy_is_lan_blocked(pol, 10001, lan_ip, 4));
    printf("LAN Blocked UID test: OK\n");

    netcap_dns_policy_destroy(pol);
    printf("ALL DNS POLICY TESTS PASSED!\n");
    return 0;
}
