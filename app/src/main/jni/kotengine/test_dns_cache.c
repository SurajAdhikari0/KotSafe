#include "dns_cache.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(void) {
    printf("=== Testing DNS Cache & Answer Parser ===\n");

    netcap_dns_cache_t *c = netcap_dns_cache_create(10);
    assert(c != NULL);

    /* 1. Basic IPv4 insert and lookup */
    uint8_t ip4[4] = {8, 8, 8, 8};
    netcap_dns_cache_insert(c, ip4, 4, "dns.google", 60);

    char domain[256] = {0};
    bool found = netcap_dns_cache_lookup(c, ip4, 4, domain, sizeof(domain));
    assert(found);
    assert(strcmp(domain, "dns.google") == 0);
    printf("1. Basic IPv4 lookup: OK (%s)\n", domain);

    /* 2. Basic IPv6 insert and lookup */
    uint8_t ip6[16] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88};
    netcap_dns_cache_insert(c, ip6, 6, "dns.google.v6", 60);

    memset(domain, 0, sizeof(domain));
    found = netcap_dns_cache_lookup(c, ip6, 6, domain, sizeof(domain));
    assert(found);
    assert(strcmp(domain, "dns.google.v6") == 0);
    printf("2. Basic IPv6 lookup: OK (%s)\n", domain);

    /* 3. Non-existent IP lookup */
    uint8_t not_found_ip[4] = {1, 2, 3, 4};
    found = netcap_dns_cache_lookup(c, not_found_ip, 4, domain, sizeof(domain));
    assert(!found);
    printf("3. Non-existent IP lookup: OK (not found)\n");

    /* 4. Parse RFC 1035 DNS response */
    /*
     * Header: ID=0x1234, Flags=0x8180 (Resp, NoError), QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
     * Question: \x06google\x03com\x00, QTYPE=1 (A), QCLASS=1 (IN)
     * Answer: \xc0\x0c (ptr to name), TYPE=1 (A), CLASS=1 (IN), TTL=300 (0x0000012c), RDLENGTH=4, RDATA=142.250.190.46
     */
    uint8_t sample_dns_resp[] = {
        0x12, 0x34,             /* ID */
        0x81, 0x80,             /* Flags: Response, NoError */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x01,             /* ANCOUNT = 1 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */
        /* Question */
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,             /* QTYPE = A */
        0x00, 0x01,             /* QCLASS = IN */
        /* Answer 1 */
        0xc0, 0x0c,             /* Pointer to google.com */
        0x00, 0x01,             /* TYPE = A */
        0x00, 0x01,             /* CLASS = IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL = 300 */
        0x00, 0x04,             /* RDLENGTH = 4 */
        142, 250, 190, 46       /* 142.250.190.46 */
    };

    netcap_dns_cache_learn_response(c, sample_dns_resp, sizeof(sample_dns_resp));

    uint8_t g_ip[4] = {142, 250, 190, 46};
    memset(domain, 0, sizeof(domain));
    found = netcap_dns_cache_lookup(c, g_ip, 4, domain, sizeof(domain));
    assert(found);
    assert(strcmp(domain, "google.com") == 0);
    printf("4. DNS Response Learning: OK (142.250.190.46 -> %s)\n", domain);

    netcap_dns_cache_destroy(c);
    printf("=== ALL DNS CACHE TESTS PASSED! ===\n");
    return 0;
}
