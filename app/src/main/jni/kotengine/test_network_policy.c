#define _POSIX_C_SOURCE 200809L
#include "network_policy.h"
#include <assert.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static bool blocks(netcap_network_policy_t *p, int uid, const char *ip, const char *domain) {
    uint8_t bytes[16] = {0};
    int family = ip && strchr(ip, ':') ? 6 : 4;
    if (ip) assert(inet_pton(family == 6 ? AF_INET6 : AF_INET, ip, bytes) == 1);
    return netcap_network_policy_blocks(p, uid, ip ? bytes : NULL, family, domain);
}
static void replace(netcap_network_policy_t *p, int source, bool enabled,
    const int32_t *uids, size_t nu, const char *const *hosts, size_t nh, const char *const *ips, size_t ni) {
    assert(netcap_network_policy_replace(p, source, enabled, uids, nu, hosts, nh, ips, ni));
}
static atomic_bool done;
static void *update_rules(void *arg) {
    netcap_network_policy_t *p = arg;
    const int32_t allowed[] = {301}, denied[] = {100};
    for (int i = 0; i < 10000; i++) {
        replace(p, NETCAP_POLICY_DENY, true, denied, 1, NULL, 0, NULL, 0);
        replace(p, NETCAP_POLICY_ALLOW, true, allowed, 1, NULL, 0, NULL, 0);
    }
    atomic_store(&done, true);
    return NULL;
}
int main(void) {
    netcap_network_policy_t *p = netcap_network_policy_create();
    assert(p);
    assert(!blocks(p, -1, "203.0.113.1", NULL));
    replace(p, NETCAP_POLICY_ALLOW, true, NULL, 0, NULL, 0, NULL, 0);
    assert(blocks(p, -1, "203.0.113.1", NULL));
    assert(blocks(p, 301, "203.0.113.1", NULL));
    const int32_t allowed[] = {301};
    const char *allow_hosts[] = {"safe.example"};
    const char *allow_ips[] = {"192.0.2.0/24", "2001:db8:1::/48"};
    replace(p, NETCAP_POLICY_ALLOW, true, allowed, 1, allow_hosts, 1, allow_ips, 2);
    assert(!blocks(p, 301, "203.0.113.1", NULL));
    assert(blocks(p, 302, "203.0.113.1", NULL));
    assert(!blocks(p, -1, "203.0.113.1", "Sub.SAFE.example."));
    assert(blocks(p, -1, "203.0.113.1", "notsafe.example"));
    assert(!blocks(p, -1, "192.0.2.5", NULL));
    assert(blocks(p, -1, "192.0.3.5", NULL));
    assert(!blocks(p, -1, "2001:db8:1::5", NULL));
    assert(blocks(p, -1, "2001:db8:2::5", NULL));
    puts("Allowlist default deny, unknown UID, app/domain/IPv4/IPv6 exceptions: OK");

    const char *feed_ips[] = {"198.51.100.9/32", "2001:db8:3::/48"};
    const char *feed_hosts[] = {"malware.example"};
    replace(p, NETCAP_POLICY_FEED, true, NULL, 0, feed_hosts, 1, feed_ips, 2);
    assert(blocks(p, 301, "198.51.100.9", NULL));
    assert(blocks(p, 301, "2001:db8:3::7", NULL));
    assert(blocks(p, 301, "203.0.113.1", "c2.malware.example"));
    const int32_t denied[] = {301};
    replace(p, NETCAP_POLICY_DENY, true, denied, 1, NULL, 0, NULL, 0);
    assert(blocks(p, 301, "192.0.2.5", "safe.example"));
    replace(p, NETCAP_POLICY_DENY, true, NULL, 0, NULL, 0, NULL, 0);
    assert(!blocks(p, 301, "203.0.113.1", NULL));
    assert(blocks(p, 301, "198.51.100.9", NULL));
    replace(p, NETCAP_POLICY_ALLOW, false, NULL, 0, NULL, 0, NULL, 0);
    assert(!blocks(p, -1, "203.0.113.1", NULL));
    assert(blocks(p, 302, "198.51.100.9", NULL));
    puts("Deny/feed precedence and independent source replacement: OK");

    const char *invalid_ips[] = {"example.com/24", "192.0.2.1/33"};
    assert(!netcap_network_policy_replace(p, NETCAP_POLICY_FEED, true, NULL, 0, NULL, 0, invalid_ips, 1));
    assert(!netcap_network_policy_replace(p, NETCAP_POLICY_FEED, true, NULL, 0, NULL, 0, invalid_ips + 1, 1));
    assert(blocks(p, 301, "198.51.100.9", NULL));
    const char *invalid_host[] = {"not a domain"};
    assert(!netcap_network_policy_replace(p, NETCAP_POLICY_FEED, true, NULL, 0, invalid_host, 1, NULL, 0));
    assert(blocks(p, 301, "203.0.113.1", "malware.example"));
    puts("Invalid replacement retains previous protection: OK");

    const int32_t blocked_uid[] = {100};
    replace(p, NETCAP_POLICY_DENY, true, blocked_uid, 1, NULL, 0, NULL, 0);
    replace(p, NETCAP_POLICY_ALLOW, true, allowed, 1, NULL, 0, NULL, 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, update_rules, p) == 0);
    do {
        assert(blocks(p, 100, "203.0.113.1", NULL));
        assert(!blocks(p, 301, "203.0.113.1", NULL));
        assert(blocks(p, 301, "198.51.100.9", NULL));
        assert(blocks(p, -1, "203.0.113.1", NULL));
    } while (!atomic_load(&done));
    assert(pthread_join(thread, NULL) == 0);
    puts("Concurrent updates preserve feed rules and default-deny enforcement: OK");
    netcap_network_policy_destroy(p);
    return 0;
}
