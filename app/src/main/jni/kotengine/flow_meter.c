#define _POSIX_C_SOURCE 200809L
#include "flow_meter.h"
#include <stdio.h>
#include <string.h>

#define EWMA_ALPHA 0.65
#define RATE_INTERVAL_MS 500
#define IDLE_DECAY_MS 1500

void netcap_flow_meter_init(netcap_flow_meter_t *fm, uint64_t now_ms) {
    if (!fm) return;
    memset(fm, 0, sizeof(*fm));
    fm->last_calc_time_ms = now_ms;
}

void netcap_flow_meter_record(netcap_flow_meter_t *fm, int is_tx, uint32_t bytes, uint64_t now_ms) {
    if (!fm) return;
    if (fm->last_calc_time_ms == 0) fm->last_calc_time_ms = now_ms;

    if (is_tx) {
        fm->interval_tx_bytes += bytes;
        fm->interval_tx_pkts++;
    } else {
        fm->interval_rx_bytes += bytes;
        fm->interval_rx_pkts++;
    }

    uint64_t delta_ms = (now_ms > fm->last_calc_time_ms) ? (now_ms - fm->last_calc_time_ms) : 0;
    if (delta_ms >= RATE_INTERVAL_MS) {
        double delta_sec = (double)delta_ms / 1000.0;

        double inst_tx_bps = (double)fm->interval_tx_bytes / delta_sec;
        double inst_rx_bps = (double)fm->interval_rx_bytes / delta_sec;
        double inst_tx_pps = (double)fm->interval_tx_pkts / delta_sec;
        double inst_rx_pps = (double)fm->interval_rx_pkts / delta_sec;

        fm->tx_bps = (fm->tx_bps == 0.0) ? inst_tx_bps : (EWMA_ALPHA * inst_tx_bps + (1.0 - EWMA_ALPHA) * fm->tx_bps);
        fm->rx_bps = (fm->rx_bps == 0.0) ? inst_rx_bps : (EWMA_ALPHA * inst_rx_bps + (1.0 - EWMA_ALPHA) * fm->rx_bps);
        fm->tx_pps = (fm->tx_pps == 0.0) ? inst_tx_pps : (EWMA_ALPHA * inst_tx_pps + (1.0 - EWMA_ALPHA) * fm->tx_pps);
        fm->rx_pps = (fm->rx_pps == 0.0) ? inst_rx_pps : (EWMA_ALPHA * inst_rx_pps + (1.0 - EWMA_ALPHA) * fm->rx_pps);

        fm->interval_tx_bytes = 0;
        fm->interval_rx_bytes = 0;
        fm->interval_tx_pkts = 0;
        fm->interval_rx_pkts = 0;
        fm->last_calc_time_ms = now_ms;
    }
}

void netcap_flow_meter_tick(netcap_flow_meter_t *fm, uint64_t now_ms) {
    if (!fm) return;
    uint64_t delta_ms = (now_ms > fm->last_calc_time_ms) ? (now_ms - fm->last_calc_time_ms) : 0;
    if (delta_ms >= IDLE_DECAY_MS) {
        fm->tx_bps *= 0.5;
        fm->rx_bps *= 0.5;
        fm->tx_pps *= 0.5;
        fm->rx_pps *= 0.5;
        if (fm->tx_bps < 1.0) fm->tx_bps = 0.0;
        if (fm->rx_bps < 1.0) fm->rx_bps = 0.0;
        if (fm->tx_pps < 0.5) fm->tx_pps = 0.0;
        if (fm->rx_pps < 0.5) fm->rx_pps = 0.0;
        fm->last_calc_time_ms = now_ms;
    }
}

void netcap_format_speed(double bps, char *out_buf, size_t buf_sz) {
    if (!out_buf || buf_sz == 0) return;

    if (bps >= 1024.0 * 1024.0 * 1024.0) {
        snprintf(out_buf, buf_sz, "%.2f GB/s", bps / (1024.0 * 1024.0 * 1024.0));
    } else if (bps >= 1024.0 * 1024.0) {
        snprintf(out_buf, buf_sz, "%.2f MB/s", bps / (1024.0 * 1024.0));
    } else if (bps >= 1024.0) {
        snprintf(out_buf, buf_sz, "%.1f KB/s", bps / 1024.0);
    } else {
        snprintf(out_buf, buf_sz, "%.0f B/s", bps);
    }
}
