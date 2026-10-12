#define _POSIX_C_SOURCE 200809L
#include "threat_detector.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#define MAX_PORT_EVENTS 256
#define PORT_SCAN_WINDOW_MS 1000
#define PORT_SCAN_THRESHOLD 15
#define ENTROPY_THRESHOLD 4.3

typedef struct {
    int32_t uid;
    uint16_t port;
    uint64_t time_ms;
} port_event_t;

struct netcap_threat_detector {
    port_event_t events[MAX_PORT_EVENTS];
    size_t event_idx;
};

netcap_threat_detector_t *netcap_threat_detector_create(void) {
    return calloc(1, sizeof(netcap_threat_detector_t));
}

void netcap_threat_detector_destroy(netcap_threat_detector_t *td) {
    free(td);
}

double netcap_calculate_shannon_entropy(const char *str, size_t len) {
    if (!str || len == 0) return 0.0;

    uint32_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[(unsigned char)str[i]]++;
    }

    double entropy = 0.0;
    double log2_factor = 1.0 / log(2.0);

    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            entropy -= p * (log(p) * log2_factor);
        }
    }
    return entropy;
}

bool netcap_threat_inspect_dns(netcap_threat_detector_t *td, int32_t uid,
                               const char *domain, netcap_threat_alert_t *out_alert) {
    (void)td;
    if (!domain || domain[0] == '\0') return false;

    /* Whitelist trusted vendor domains to prevent false DGA detections */
    if (strstr(domain, "google") || strstr(domain, "gstatic") ||
        strstr(domain, "apple") || strstr(domain, "samsung") ||
        strstr(domain, "cloudflare") || strstr(domain, "facebook") ||
        strstr(domain, "whatsapp") || strstr(domain, "microsoft")) {
        return false;
    }

    size_t dlen = strlen(domain);
    /* Find first label (subdomain) */
    const char *dot = strchr(domain, '.');
    size_t label_len = dot ? (size_t)(dot - domain) : dlen;

    /* If label is long (>18 chars) and has high Shannon entropy, it's likely tunneling/DGA */
    if (label_len >= 18) {
        double ent = netcap_calculate_shannon_entropy(domain, label_len);
        if (ent >= ENTROPY_THRESHOLD) {
            if (out_alert) {
                out_alert->type = THREAT_DNS_TUNNELING;
                out_alert->uid = uid;
                snprintf(out_alert->details, sizeof(out_alert->details),
                         "DNS Tunneling / DGA detected: '%.32s...' (Entropy: %.2f)", domain, ent);
            }
            return true;
        }
    }
    return false;
}

bool netcap_threat_inspect_flow(netcap_threat_detector_t *td, int32_t uid,
                                uint16_t dst_port, uint64_t now_ms,
                                netcap_threat_alert_t *out_alert) {
    if (!td) return false;

    /* 1. Check for suspicious backdoor / mining ports */
    if (dst_port == 4444 || dst_port == 6667 || dst_port == 3333 || dst_port == 1337 || dst_port == 5555) {
        if (out_alert) {
            out_alert->type = THREAT_SUSPICIOUS_PORT;
            out_alert->uid = uid;
            snprintf(out_alert->details, sizeof(out_alert->details),
                     "Access to suspicious security port: %u", dst_port);
            out_alert->timestamp_ms = now_ms;
        }
        return true;
    }

    if (uid < 0) return false;

    /* 2. Record port access event in ring */
    td->events[td->event_idx].uid = uid;
    td->events[td->event_idx].port = dst_port;
    td->events[td->event_idx].time_ms = now_ms;
    td->event_idx = (td->event_idx + 1) % MAX_PORT_EVENTS;

    /* 3. Count unique ports accessed by this UID within the time window */
    uint16_t seen_ports[PORT_SCAN_THRESHOLD + 1];
    size_t seen_count = 0;

    for (size_t i = 0; i < MAX_PORT_EVENTS; i++) {
        if (td->events[i].uid == uid &&
            now_ms >= td->events[i].time_ms &&
            (now_ms - td->events[i].time_ms) <= PORT_SCAN_WINDOW_MS) {

            uint16_t p = td->events[i].port;
            int found = 0;
            for (size_t k = 0; k < seen_count; k++) {
                if (seen_ports[k] == p) { found = 1; break; }
            }
            if (!found) {
                seen_ports[seen_count++] = p;
                if (seen_count >= PORT_SCAN_THRESHOLD) {
                    if (out_alert) {
                        out_alert->type = THREAT_PORT_SCAN;
                        out_alert->uid = uid;
                        snprintf(out_alert->details, sizeof(out_alert->details),
                                 "Port scan detected: %zu distinct ports probed within 1s", seen_count);
                        out_alert->timestamp_ms = now_ms;
                    }
                    return true;
                }
            }
        }
    }

    return false;
}
