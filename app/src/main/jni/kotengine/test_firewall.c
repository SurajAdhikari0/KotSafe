#include "firewall.h"
#include <stdio.h>
#include <assert.h>

int main(void) {
    printf("=== Testing Native Firewall Engine ===\n");

    netcap_firewall_t *fw = netcap_firewall_create();
    assert(fw != NULL);

    /* 1. UID Blocking test */
    int32_t blocked_uids[] = {10050, 10099, 10123};
    netcap_firewall_set_blocked_uids(fw, blocked_uids, 3);

    assert(netcap_firewall_is_uid_blocked(fw, 10050));
    assert(netcap_firewall_is_uid_blocked(fw, 10099));
    assert(netcap_firewall_is_uid_blocked(fw, 10123));
    assert(!netcap_firewall_is_uid_blocked(fw, 1000));
    assert(!netcap_firewall_is_uid_blocked(fw, 10051));
    printf("1. UID Blocking: OK\n");

    /* 2. Domain Blocking test */
    netcap_firewall_add_blocked_domain(fw, "doubleclick.net");
    netcap_firewall_add_blocked_domain(fw, "malware-c2.xyz");
    assert(netcap_firewall_blocked_domains_count(fw) == 2);

    /* Exact matches */
    assert(netcap_firewall_is_domain_blocked(fw, "doubleclick.net"));
    assert(netcap_firewall_is_domain_blocked(fw, "malware-c2.xyz"));

    /* Suffix / Subdomain matches */
    assert(netcap_firewall_is_domain_blocked(fw, "ad.doubleclick.net"));
    assert(netcap_firewall_is_domain_blocked(fw, "tracker.v2.doubleclick.net"));

    /* Non-blocked */
    assert(!netcap_firewall_is_domain_blocked(fw, "google.com"));
    assert(!netcap_firewall_is_domain_blocked(fw, "notdoubleclick.net"));
    printf("2. Domain & Subdomain Blocking: OK\n");

    /* 3. Removal & Clear */
    netcap_firewall_remove_blocked_domain(fw, "doubleclick.net");
    assert(!netcap_firewall_is_domain_blocked(fw, "doubleclick.net"));
    assert(!netcap_firewall_is_domain_blocked(fw, "ad.doubleclick.net"));
    assert(netcap_firewall_is_domain_blocked(fw, "malware-c2.xyz"));

    netcap_firewall_clear_blocked_domains(fw);
    assert(!netcap_firewall_is_domain_blocked(fw, "malware-c2.xyz"));
    assert(netcap_firewall_blocked_domains_count(fw) == 0);
    printf("3. Removal & Clear: OK\n");

    netcap_firewall_destroy(fw);
    printf("=== ALL FIREWALL TESTS PASSED! ===\n");
    return 0;
}
