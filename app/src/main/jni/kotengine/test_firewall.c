#include "firewall.h"
#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>

static atomic_bool updates_done;
static void *replace_uids(void *arg) {
    netcap_firewall_t *fw = arg;
    int32_t ids[256];
    for (int i = 0; i < 256; i++) ids[i] = 10000 + i;
    for (int i = 0; i < 100000; i++)
        netcap_firewall_set_blocked_uids(fw, ids, 256);
    atomic_store(&updates_done, true);
    return NULL;
}


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

    /* UID 10123 remains blocked throughout concurrent policy replacement. */
    pthread_t writer;
    assert(pthread_create(&writer, NULL, replace_uids, fw) == 0);
    do {
        assert(netcap_firewall_is_uid_blocked(fw, 10123));
        assert(!netcap_firewall_is_uid_blocked(fw, 9999));
    } while (!atomic_load(&updates_done));
    assert(pthread_join(writer, NULL) == 0);
    netcap_firewall_set_blocked_uids(fw, NULL, 0);
    assert(!netcap_firewall_is_uid_blocked(fw, 10123));
    printf("4. Concurrent replacement and explicit clear: OK\n");

    netcap_firewall_destroy(fw);
    printf("=== ALL FIREWALL TESTS PASSED! ===\n");
    return 0;
}
