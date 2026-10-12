#ifndef NETCAP_FLOW_METER_H
#define NETCAP_FLOW_METER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t last_calc_time_ms;
    uint64_t interval_tx_bytes;
    uint64_t interval_rx_bytes;
    uint32_t interval_tx_pkts;
    uint32_t interval_rx_pkts;

    /* Smoothed EWMA rates */
    double tx_bps; /* bytes per second */
    double rx_bps; /* bytes per second */
    double tx_pps; /* packets per second */
    double rx_pps; /* packets per second */
} netcap_flow_meter_t;

/* Initializes a flow meter */
void netcap_flow_meter_init(netcap_flow_meter_t *fm, uint64_t now_ms);

/* Records bytes and packets transferred, updating EWMA rate when interval elapsed */
void netcap_flow_meter_record(netcap_flow_meter_t *fm, int is_tx, uint32_t bytes, uint64_t now_ms);

/* Recalculates rate if idle (decays to 0 if connection stopped transferring) */
void netcap_flow_meter_tick(netcap_flow_meter_t *fm, uint64_t now_ms);

/* Formats rate into human-readable string (e.g., "1.45 MB/s", "340 KB/s", "12 B/s") */
void netcap_format_speed(double bps, char *out_buf, size_t buf_sz);

#ifdef __cplusplus
}
#endif

#endif /* NETCAP_FLOW_METER_H */
