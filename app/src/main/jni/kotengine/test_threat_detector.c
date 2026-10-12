#include "threat_detector.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    printf("--- Testing Real-Time Threat Detector & Shannon Entropy ---\n");

    /* 1. Test Shannon Entropy on normal domain vs. exfiltration tunneling domain */
    const char *normal = "google";
    double normal_ent = netcap_calculate_shannon_entropy(normal, strlen(normal));
    printf("Shannon entropy of '%s': %.2f bits\n", normal, normal_ent);
    assert(normal_ent < 3.0);

    const char *tunnel_domain = "7f8b9c2a1d4e5f608192a3b4c5d6e7f8.evil-c2.com";
    double tunnel_ent = netcap_calculate_shannon_entropy(tunnel_domain, 32);
    printf("Shannon entropy of tunnel subdomain: %.2f bits\n", tunnel_ent);
    assert(tunnel_ent > 3.6);

    netcap_threat_detector_t *td = netcap_threat_detector_create();
    assert(td != NULL);

    netcap_threat_alert_t alert;
    memset(&alert, 0, sizeof(alert));
    bool is_threat = netcap_threat_inspect_dns(td, 10150, tunnel_domain, &alert);
    assert(is_threat == true);
    assert(alert.type == THREAT_DNS_TUNNELING);
    printf("DNS Tunneling Detection: OK -> '%s'\n", alert.details);

    /* 2. Test Suspicious Port Detection */
    memset(&alert, 0, sizeof(alert));
    assert(netcap_threat_inspect_flow(td, 10150, 4444, 1000, &alert) == true);
    assert(alert.type == THREAT_SUSPICIOUS_PORT);
    printf("Suspicious Port Detection (4444): OK -> '%s'\n", alert.details);

    /* 3. Test Port Scan Detection */
    bool scan_detected = false;
    for (uint16_t p = 1000; p < 1020; p++) {
        if (netcap_threat_inspect_flow(td, 10200, p, 2000, &alert)) {
            if (alert.type == THREAT_PORT_SCAN) {
                scan_detected = true;
                break;
            }
        }
    }
    assert(scan_detected == true);
    printf("Port Scan Detection: OK -> '%s'\n", alert.details);

    netcap_threat_detector_destroy(td);
    printf("ALL THREAT DETECTOR TESTS PASSED!\n");
    return 0;
}
