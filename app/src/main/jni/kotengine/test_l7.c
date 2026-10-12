#include "l7_inspect.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Synthetic TLS 1.2 ClientHello with SNI = "api.github.com" */
static const uint8_t sample_tls_client_hello[] = {
    0x16, 0x03, 0x01, 0x00, 0x5a, /* Record header: Handshake, TLS 1.0, len 90 */
    0x01, 0x00, 0x00, 0x56,       /* Handshake type 1 (ClientHello), len 86 */
    0x03, 0x03,                   /* Client version: TLS 1.2 */
    /* 32 bytes random */
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
    0x00,                         /* Session ID len 0 */
    0x00, 0x02, 0xc0, 0x2f,       /* Cipher suites len 2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    0x01, 0x00,                   /* Compression methods len 1, null */
    0x00, 0x21,                   /* Extensions len 33 */
    /* Extension 0x0000 (SNI), len 19 */
    0x00, 0x00, 0x00, 0x13,
    0x00, 0x11,                   /* Server name list len 17 */
    0x00,                         /* Name type 0 (hostname) */
    0x00, 0x0e,                   /* Hostname len 14 */
    'a','p','i','.','g','i','t','h','u','b','.','c','o','m',
    /* Extension 0x000d (Signature algorithms), len 4 (dummy) */
    0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01
};

/* Synthetic DNS Query for "google.com" */
static const uint8_t sample_dns_query[] = {
    0x12, 0x34,                   /* ID */
    0x01, 0x00,                   /* Flags: standard query */
    0x00, 0x01,                   /* QDCOUNT = 1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ANCOUNT, NSCOUNT, ARCOUNT */
    /* QNAME: 6 'google' 3 'com' 0 */
    0x06, 'g','o','o','g','l','e',
    0x03, 'c','o','m',
    0x00,
    0x00, 0x01,                   /* QTYPE A */
    0x00, 0x01                    /* QCLASS IN */
};

/* Synthetic HTTP GET with Host: example.com */
static const char sample_http_request[] = 
    "GET /index.html HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "User-Agent: Mozilla/5.0\r\n\r\n";

int main(void) {
    netcap_l7_info_t info;

    /* 1. Test TLS ClientHello SNI */
    bool ok = netcap_l7_inspect(6, 49152, 443, sample_tls_client_hello, sizeof(sample_tls_client_hello), &info);
    assert(ok);
    assert(info.has_domain);
    assert(strcmp(info.domain, "api.github.com") == 0);
    assert(strcmp(info.protocol, "TLS") == 0);
    printf("TLS SNI Test: OK -> domain='%s', proto='%s'\n", info.domain, info.protocol);

    /* 2. Test DNS QNAME */
    ok = netcap_l7_inspect(17, 54321, 53, sample_dns_query, sizeof(sample_dns_query), &info);
    assert(ok);
    assert(info.has_domain);
    assert(strcmp(info.domain, "google.com") == 0);
    assert(strcmp(info.protocol, "DNS") == 0);
    printf("DNS Query Test: OK -> domain='%s', proto='%s'\n", info.domain, info.protocol);

    /* 3. Test HTTP Host */
    ok = netcap_l7_inspect(6, 40000, 80, (const uint8_t *)sample_http_request, strlen(sample_http_request), &info);
    assert(ok);
    assert(info.has_domain);
    assert(strcmp(info.domain, "example.com") == 0);
    assert(strcmp(info.protocol, "HTTP") == 0);
    printf("HTTP Host Test: OK -> domain='%s', proto='%s'\n", info.domain, info.protocol);

    printf("ALL L7 INSPECT TESTS PASSED!\n");
    return 0;
}
