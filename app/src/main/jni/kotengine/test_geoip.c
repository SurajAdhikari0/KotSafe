#include "geoip.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    uint8_t local_ip[4] = {192, 168, 1, 100};
    uint8_t google_ip[4] = {8, 8, 8, 8};
    uint8_t cf_ip[4] = {1, 1, 1, 1};
    uint8_t quad9_ip[4] = {9, 9, 9, 9};
    uint8_t in_ip[4] = {103, 200, 1, 1};
    uint8_t jp_ip[4] = {133, 5, 1, 1};

    assert(strcmp(netcap_geoip_lookup(local_ip, 4), "LO") == 0);
    assert(strcmp(netcap_geoip_lookup(google_ip, 4), "US") == 0);
    assert(strcmp(netcap_geoip_lookup(cf_ip, 4), "US") == 0);
    assert(strcmp(netcap_geoip_lookup(quad9_ip, 4), "CH") == 0);
    assert(strcmp(netcap_geoip_lookup(in_ip, 4), "IN") == 0);
    assert(strcmp(netcap_geoip_lookup(jp_ip, 4), "JP") == 0);

    printf("Local IP -> %s\n", netcap_geoip_lookup(local_ip, 4));
    printf("8.8.8.8  -> %s\n", netcap_geoip_lookup(google_ip, 4));
    printf("1.1.1.1  -> %s\n", netcap_geoip_lookup(cf_ip, 4));
    printf("9.9.9.9  -> %s\n", netcap_geoip_lookup(quad9_ip, 4));
    printf("India IP -> %s\n", netcap_geoip_lookup(in_ip, 4));
    printf("Japan IP -> %s\n", netcap_geoip_lookup(jp_ip, 4));

    printf("ALL GEOIP TESTS PASSED!\n");
    return 0;
}
