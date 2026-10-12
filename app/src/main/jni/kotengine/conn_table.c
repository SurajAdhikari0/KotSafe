#include "conn_table.h"
#include "payload_buffer.h"
#include <stdlib.h>
#include <string.h>

/*
 * Layout: a flat array of `capacity` netcap_conn_t slots. A separate
 * bucket-head array of size `nbuckets` (next power of two >= capacity*1.3)
 * holds indices into the slot array; collisions are chained via
 * `_hash_next`. A free list threads unused slots. The LRU list is
 * doubly-linked through `_lru_prev` / `_lru_next` over slot indices,
 * with NETCAP_NIL as the sentinel.
 */

#define NETCAP_NIL UINT32_MAX

struct netcap_conn_table {
    netcap_conn_t *slots;
    uint32_t capacity;

    uint32_t *buckets;
    uint32_t nbuckets;
    uint32_t bucket_mask;

    uint32_t free_head;   /* singly-linked free list via _hash_next */
    uint32_t count;

    uint32_t lru_head;    /* least recently used */
    uint32_t lru_tail;    /* most recently used */

    uint64_t next_id;

    netcap_conn_evict_cb on_evict;
    void *user_data;
};

static uint32_t next_pow2(uint32_t n) {
    uint32_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

static uint32_t hash_key(const netcap_flow_key_t *k) {
    /* FNV-1a over the fixed-size key struct */
    uint32_t h = 2166136261u;
    const uint8_t *p = (const uint8_t *)k;
    for (size_t i = 0; i < sizeof(*k); i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static int key_eq(const netcap_flow_key_t *a, const netcap_flow_key_t *b) {
    return memcmp(a, b, sizeof(*a)) == 0;
}

netcap_conn_table_t *netcap_conn_table_create(uint32_t capacity,
                                               netcap_conn_evict_cb on_evict,
                                               void *user_data) {
    if (capacity == 0) return NULL;
    netcap_conn_table_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->capacity = capacity;
    t->slots = calloc(capacity, sizeof(netcap_conn_t));
    t->nbuckets = next_pow2(capacity + capacity / 3 + 1);
    t->bucket_mask = t->nbuckets - 1;
    t->buckets = malloc(t->nbuckets * sizeof(uint32_t));
    if (!t->slots || !t->buckets) {
        free(t->slots); free(t->buckets); free(t);
        return NULL;
    }
    for (uint32_t i = 0; i < t->nbuckets; i++) t->buckets[i] = NETCAP_NIL;

    /* build free list: slot i's _hash_next points to i+1 */
    for (uint32_t i = 0; i < capacity; i++) {
        t->slots[i]._occupied = 0;
        t->slots[i]._hash_next = (i + 1 < capacity) ? i + 1 : NETCAP_NIL;
    }
    t->free_head = 0;
    t->lru_head = NETCAP_NIL;
    t->lru_tail = NETCAP_NIL;
    t->on_evict = on_evict;
    t->user_data = user_data;
    t->next_id = 1;
    return t;
}

void netcap_conn_table_destroy(netcap_conn_table_t *t) {
    if (!t) return;
    for (uint32_t i = 0; i < t->capacity; i++) {
        if (t->slots[i]._occupied) {
            if (t->slots[i].payload_buf) {
                netcap_payload_buf_destroy((netcap_payload_buf_t *)t->slots[i].payload_buf);
            }
            if (t->slots[i].flow_meter) {
                free(t->slots[i].flow_meter);
            }
        }
    }
    free(t->slots);
    free(t->buckets);
    free(t);
}

static void lru_unlink(netcap_conn_table_t *t, uint32_t idx) {
    netcap_conn_t *s = &t->slots[idx];
    uint32_t prev = s->_lru_prev, next = s->_lru_next;
    if (prev != NETCAP_NIL) t->slots[prev]._lru_next = next;
    else t->lru_head = next;
    if (next != NETCAP_NIL) t->slots[next]._lru_prev = prev;
    else t->lru_tail = prev;
    s->_lru_prev = s->_lru_next = NETCAP_NIL;
}

static void lru_push_mru(netcap_conn_table_t *t, uint32_t idx) {
    netcap_conn_t *s = &t->slots[idx];
    s->_lru_prev = t->lru_tail;
    s->_lru_next = NETCAP_NIL;
    if (t->lru_tail != NETCAP_NIL) t->slots[t->lru_tail]._lru_next = idx;
    else t->lru_head = idx;
    t->lru_tail = idx;
}

static void bucket_remove(netcap_conn_table_t *t, uint32_t bucket, uint32_t idx) {
    uint32_t cur = t->buckets[bucket], prev = NETCAP_NIL;
    while (cur != NETCAP_NIL) {
        if (cur == idx) {
            if (prev == NETCAP_NIL) t->buckets[bucket] = t->slots[cur]._hash_next;
            else t->slots[prev]._hash_next = t->slots[cur]._hash_next;
            return;
        }
        prev = cur;
        cur = t->slots[cur]._hash_next;
    }
}

static void evict_slot(netcap_conn_table_t *t, uint32_t idx) {
    netcap_conn_t *s = &t->slots[idx];
    if (t->on_evict && !s->closed) t->on_evict(s, t->user_data);   /* tombstones already reported */

    uint32_t bucket = hash_key(&s->key) & t->bucket_mask;
    bucket_remove(t, bucket, idx);
    lru_unlink(t, idx);

    if (s->payload_buf) {
        netcap_payload_buf_destroy((netcap_payload_buf_t *)s->payload_buf);
        s->payload_buf = NULL;
    }
    if (s->flow_meter) {
        free(s->flow_meter);
        s->flow_meter = NULL;
    }

    memset(s, 0, sizeof(*s));
    s->_occupied = 0;
    s->_hash_next = t->free_head;
    t->free_head = idx;
    t->count--;
}

void netcap_conn_table_remove(netcap_conn_table_t *t, const netcap_flow_key_t *key) {
    uint32_t bucket = hash_key(key) & t->bucket_mask;
    uint32_t cur = t->buckets[bucket];
    while (cur != NETCAP_NIL) {
        if (t->slots[cur]._occupied && key_eq(&t->slots[cur].key, key)) {
            evict_slot(t, cur);
            return;
        }
        cur = t->slots[cur]._hash_next;
    }
}

static netcap_conn_t *find_slot(netcap_conn_table_t *t, const netcap_flow_key_t *key, uint32_t *idx_out) {
    uint32_t cur = t->buckets[hash_key(key) & t->bucket_mask];
    while (cur != NETCAP_NIL) {
        if (t->slots[cur]._occupied && key_eq(&t->slots[cur].key, key)) {
            if (idx_out) *idx_out = cur;
            return &t->slots[cur];
        }
        cur = t->slots[cur]._hash_next;
    }
    return NULL;
}

netcap_conn_t *netcap_conn_table_find(netcap_conn_table_t *t, const netcap_flow_key_t *key) {
    return find_slot(t, key, NULL);
}

netcap_conn_t *netcap_conn_table_open(netcap_conn_table_t *t, const netcap_flow_key_t *key,
                                      int is_new_flow, time_t now, int *created) {
    if (created) *created = 0;
    uint32_t idx = NETCAP_NIL;
    netcap_conn_t *s = find_slot(t, key, &idx);

    if (s && !s->closed) {
        s->last_seen = now;
        lru_unlink(t, idx);
        lru_push_mru(t, idx);
        return s;
    }
    if (s) {                         /* tombstone */
        if (!is_new_flow) return s;  /* late packet: do not resurrect, do not duplicate */
        evict_slot(t, idx);          /* genuine tuple reuse: drop the old record */
    } else if (!is_new_flow) {
        return NULL;                 /* mid-stream with no flow: never create */
    }

    /* allocate, evicting a tombstone first, then the LRU live entry */
    if (t->free_head == NETCAP_NIL) {
        uint32_t victim = NETCAP_NIL;
        for (uint32_t i = t->lru_head; i != NETCAP_NIL; i = t->slots[i]._lru_next)
            if (t->slots[i].closed) { victim = i; break; }
        if (victim == NETCAP_NIL) victim = t->lru_head;
        if (victim == NETCAP_NIL) return NULL;
        evict_slot(t, victim);       /* on_evict runs first for live entries */
    }

    uint32_t nidx = t->free_head;
    t->free_head = t->slots[nidx]._hash_next;

    s = &t->slots[nidx];
    memset(s, 0, sizeof(*s));
    s->key = *key;
    s->conn_id = t->next_id++;
    s->first_seen = s->last_seen = now;
    s->uid = -1;
    s->_occupied = 1;

    uint32_t bucket = hash_key(key) & t->bucket_mask;
    s->_hash_next = t->buckets[bucket];
    t->buckets[bucket] = nidx;

    s->_lru_prev = s->_lru_next = NETCAP_NIL;
    lru_push_mru(t, nidx);

    t->count++;
    if (created) *created = 1;
    return s;
}

/* Legacy find-or-create. Kept for tests/back-compat; new code must use open()/find(). */
netcap_conn_t *netcap_conn_table_touch(netcap_conn_table_t *t,
                                        const netcap_flow_key_t *key,
                                        time_t now) {
    return netcap_conn_table_open(t, key, 1, now, NULL);
}

void netcap_conn_table_close(netcap_conn_table_t *t, netcap_conn_t *c, time_t now) {
    if (!c || c->closed) return;
    if (t->on_evict) t->on_evict(c, t->user_data);
    c->closed = 1;
    c->closed_at = now;
}

void netcap_conn_table_sweep_idle(netcap_conn_table_t *t, time_t now, uint32_t idle_secs) {
    /* reap expired tombstones (they are not LRU-ordered by closed_at) */
    for (uint32_t i = t->lru_head; i != NETCAP_NIL; ) {
        uint32_t nx = t->slots[i]._lru_next;
        if (t->slots[i].closed && (now - t->slots[i].closed_at) >= NETCAP_TOMBSTONE_SECS) evict_slot(t, i);
        i = nx;
    }
    uint32_t cur = t->lru_head;
    while (cur != NETCAP_NIL) {
        uint32_t next = t->slots[cur]._lru_next; /* capture before eviction mutates links */
        if ((uint32_t)(now - t->slots[cur].last_seen) < idle_secs) break; /* LRU-ordered: rest are newer */
        evict_slot(t, cur);
        cur = next;
    }
}

uint32_t netcap_conn_table_count(const netcap_conn_table_t *t) {
    return t->count;
}

void netcap_conn_table_foreach(const netcap_conn_table_t *t,
                                netcap_conn_iter_cb cb, void *user_data) {
    for (uint32_t idx = t->lru_head; idx != NETCAP_NIL; idx = t->slots[idx]._lru_next) {
        if (t->slots[idx].closed) continue;
        if (cb(&t->slots[idx], user_data) != 0) return;
    }
}
