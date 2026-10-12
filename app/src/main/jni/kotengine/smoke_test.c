#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "conn_table.h"
#include "blacklist.h"
#include "ring_log.h"

static int evict_count = 0;
static void on_evict(const netcap_conn_t *c, void *ud) {
    (void)c; (void)ud;
    evict_count++;
}

static void test_conn_table_basic(void) {
    netcap_conn_table_t *t = netcap_conn_table_create(4, on_evict, NULL);
    assert(t);

    netcap_flow_key_t k1 = {.proto = 6, .family = 4, .src_port = 1234, .dst_port = 443};
    k1.src_ip[0] = 10; k1.dst_ip[0] = 93;

    netcap_conn_t *c1 = netcap_conn_table_touch(t, &k1, 100);
    assert(c1);
    c1->bytes_sent += 500;

    /* same key again -> same slot, updated */
    netcap_conn_t *c1b = netcap_conn_table_touch(t, &k1, 101);
    assert(c1b == c1);
    assert(c1b->bytes_sent == 500);
    assert(netcap_conn_table_count(t) == 1);

    /* fill to capacity with distinct keys */
    for (int i = 0; i < 3; i++) {
        netcap_flow_key_t k = k1;
        k.src_port = 2000 + i;
        netcap_conn_table_touch(t, &k, 102 + i);
    }
    assert(netcap_conn_table_count(t) == 4);

    /* one more -> evicts LRU (k1 was touched most recently above at t=101,
     * so it should survive; the least recently touched among the fillers
     * should go - but since we touched c1 first then added 3 more without
     * re-touching it, k1 is actually the LRU head now until fresh touches
     * push it back... verify behavior explicitly instead of assuming */
    evict_count = 0;
    netcap_flow_key_t k5 = k1; k5.src_port = 9999;
    netcap_conn_table_touch(t, &k5, 110);
    assert(evict_count == 1);
    assert(netcap_conn_table_count(t) == 4);

    netcap_conn_table_destroy(t);
    printf("conn_table basic: OK\n");
}

static void test_conn_table_idle_sweep(void) {
    netcap_conn_table_t *t = netcap_conn_table_create(8, NULL, NULL);
    netcap_flow_key_t k = {.proto = 17, .family = 4, .src_port = 1, .dst_port = 2};
    netcap_conn_table_touch(t, &k, 1000);
    netcap_conn_table_sweep_idle(t, 1005, 10); /* idle 5s < 10s threshold, keep */
    assert(netcap_conn_table_count(t) == 1);
    netcap_conn_table_sweep_idle(t, 1020, 10); /* idle 20s >= 10s, evict */
    assert(netcap_conn_table_count(t) == 0);
    netcap_conn_table_destroy(t);
    printf("conn_table idle sweep: OK\n");
}

static void test_blacklist(void) {
    netcap_blacklist_t *bl = netcap_blacklist_create();
    uint8_t addr[4] = {93, 184, 216, 34}; /* example.com-ish */
    uint8_t cidr[4] = {93, 184, 216, 0};
    netcap_blacklist_add(bl, cidr, 4, 24);

    assert(netcap_blacklist_match(bl, addr, 4) == 1);

    uint8_t other[4] = {8, 8, 8, 8};
    assert(netcap_blacklist_match(bl, other, 4) == 0);

    assert(netcap_blacklist_rule_count(bl, 4) == 1);
    netcap_blacklist_remove_all(bl, 4);
    assert(netcap_blacklist_match(bl, addr, 4) == 0);

    netcap_blacklist_destroy(bl);
    printf("blacklist: OK\n");
}

static void test_ring_log(void) {
    netcap_ring_log_t r;
    netcap_ring_log_init(&r, 4);
    for (int i = 0; i < 6; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "msg%d", i);
        netcap_ring_log_push(&r, 1, msg);
    }
    /* capacity 4, pushed 6 -> 2 dropped */
    assert(netcap_ring_log_dropped_count(&r) == 2);

    netcap_log_rec_t out[8];
    uint32_t n = netcap_ring_log_drain(&r, out, 8);
    assert(n == 4);
    assert(strcmp(out[0].msg, "msg2") == 0); /* oldest surviving */
    assert(strcmp(out[3].msg, "msg5") == 0);

    netcap_ring_log_destroy(&r);
    printf("ring_log: OK\n");
}

int main(void) {
    test_conn_table_basic();
    test_conn_table_idle_sweep();
    test_blacklist();
    test_ring_log();
    printf("ALL TESTS PASSED\n");
    return 0;
}
