#ifndef NETCAP_GEOIP_H
#define NETCAP_GEOIP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Resolves an IPv4 or IPv6 address to a 2-letter ISO country code (e.g. "US", "DE", "IN").
 * If the IP is a private/loopback/local address, returns "LO".
 * If unmapped, returns "ZZ" or an empty string.
 */
const char *netcap_geoip_lookup(const uint8_t *ip, uint8_t family);

/*
 * Optional: Load an external GeoIP CSV / CIDR mapping file (e.g., GeoLite2 or custom feed)
 * Format per line: start_ip,end_ip,country_code or cidr,country_code
 * Returns number of rules loaded, or -1 on error.
 */
int netcap_geoip_load_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_GEOIP_H */
