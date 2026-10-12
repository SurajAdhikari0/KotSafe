#include "flow_meter.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    printf("--- Testing Real-Time EWMA Flow Meter ---\n");

    netcap_flow_meter_t fm;
    netcap_flow_meter_init(&fm, 1000);

    /* Record 500 KB over 500ms (should be ~1 MB/s) */
    netcap_flow_meter_record(&fm, 1, 250 * 1024, 1200);
    netcap_flow_meter_record(&fm, 1, 250 * 1024, 1500);

    assert(fm.tx_bps > 900000.0 && fm.tx_bps < 1100000.0);
    printf("EWMA 1 MB/s Tx test: OK (%.0f B/s)\n", fm.tx_bps);

    char speed_str[32];
    netcap_format_speed(fm.tx_bps, speed_str, sizeof(speed_str));
    printf("Formatted Speed: '%s'\n", speed_str);
    assert(strstr(speed_str, "MB/s") != NULL || strstr(speed_str, "KB/s") != NULL);

    /* Test idle decay */
    netcap_flow_meter_tick(&fm, 3500); /* 2 seconds later */
    assert(fm.tx_bps < 600000.0);
    printf("EWMA Idle decay: OK (decayed to %.0f B/s)\n", fm.tx_bps);

    printf("ALL FLOW METER TESTS PASSED!\n");
    return 0;
}
