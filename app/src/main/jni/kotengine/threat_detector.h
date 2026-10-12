#ifndef NETCAP_THREAT_DETECTOR_H
#define NETCAP_THREAT_DETECTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    THREAT_NONE = 0,
    THREAT_DNS_TUNNELING = 1,   /* High Shannon entropy in DNS query name */
    THREAT_PORT_SCAN = 2,       /* App scanning multiple destination ports */
    THREAT_SUSPICIOUS_PORT = 4  /* Known malware/IRC/mining ports (e.g. 6667, 3333, 4444) */
} netcap_threat_type_t;

typedef struct {
    netcap_threat_type_t type;
    int32_t uid;
    char details[128];
    uint64_t timestamp_ms;
} netcap_threat_alert_t;

typedef struct netcap_threat_detector netcap_threat_detector_t;

netcap_threat_detector_t *netcap_threat_detector_create(void);
void netcap_threat_detector_destroy(netcap_threat_detector_t *td);

/* Computes Shannon entropy of a string (in bits, 0.0 to 8.0) */
double netcap_calculate_shannon_entropy(const char *str, size_t len);

/* Evaluates a DNS domain name for tunneling/DGA exfiltration.
 * Returns true and populates alert if entropy exceeds threshold (e.g. 3.8). */
bool netcap_threat_inspect_dns(netcap_threat_detector_t *td, int32_t uid,
                               const char *domain, netcap_threat_alert_t *out_alert);

/* Evaluates destination port access for port scanning or known malicious ports.
 * Returns true and populates alert if a scan or suspicious port is detected. */
bool netcap_threat_inspect_flow(netcap_threat_detector_t *td, int32_t uid,
                                uint16_t dst_port, uint64_t now_ms,
                                netcap_threat_alert_t *out_alert);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_THREAT_DETECTOR_H */
