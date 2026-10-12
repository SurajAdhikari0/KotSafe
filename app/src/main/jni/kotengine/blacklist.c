#include "blacklist.h"
#include <stdlib.h>
#include <string.h>

typedef struct trie_node {
    struct trie_node *child[2];
    uint8_t blocked; /* a CIDR rule terminates exactly here */
} trie_node_t;

struct netcap_blacklist {
    trie_node_t *v4_root;
    trie_node_t *v6_root;
    size_t v4_rules;
    size_t v6_rules;
};

static trie_node_t *node_new(void) {
    return calloc(1, sizeof(trie_node_t));
}

static void node_free(trie_node_t *n) {
    if (!n) return;
    node_free(n->child[0]);
    node_free(n->child[1]);
    free(n);
}

static int get_bit(const uint8_t *addr, int bit_index) {
    return (addr[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
}

netcap_blacklist_t *netcap_blacklist_create(void) {
    netcap_blacklist_t *bl = calloc(1, sizeof(*bl));
    if (!bl) return NULL;
    bl->v4_root = node_new();
    bl->v6_root = node_new();
    if (!bl->v4_root || !bl->v6_root) {
        node_free(bl->v4_root);
        node_free(bl->v6_root);
        free(bl);
        return NULL;
    }
    return bl;
}

void netcap_blacklist_destroy(netcap_blacklist_t *bl) {
    if (!bl) return;
    node_free(bl->v4_root);
    node_free(bl->v6_root);
    free(bl);
}

void netcap_blacklist_add(netcap_blacklist_t *bl, const uint8_t *addr,
                           uint8_t family, uint8_t prefix_len) {
    trie_node_t *n = (family == 4) ? bl->v4_root : bl->v6_root;
    uint8_t max_len = (family == 4) ? 32 : 128;
    if (prefix_len > max_len) prefix_len = max_len;

    for (int i = 0; i < prefix_len; i++) {
        int bit = get_bit(addr, i);
        if (!n->child[bit]) n->child[bit] = node_new();
        n = n->child[bit];
    }
    if (!n->blocked) {
        n->blocked = 1;
        if (family == 4) bl->v4_rules++; else bl->v6_rules++;
    }
}

void netcap_blacklist_remove_all(netcap_blacklist_t *bl, uint8_t family) {
    if (family == 4) {
        node_free(bl->v4_root);
        bl->v4_root = node_new();
        bl->v4_rules = 0;
    } else {
        node_free(bl->v6_root);
        bl->v6_root = node_new();
        bl->v6_rules = 0;
    }
}

int netcap_blacklist_match(const netcap_blacklist_t *bl, const uint8_t *addr, uint8_t family) {
    trie_node_t *n = (family == 4) ? bl->v4_root : bl->v6_root;
    uint8_t max_len = (family == 4) ? 32 : 128;
    if (n->blocked) return 1; /* 0.0.0.0/0 style catch-all */

    for (int i = 0; i < max_len && n; i++) {
        int bit = get_bit(addr, i);
        n = n->child[bit];
        if (n && n->blocked) return 1;
    }
    return 0;
}

size_t netcap_blacklist_rule_count(const netcap_blacklist_t *bl, uint8_t family) {
    return (family == 4) ? bl->v4_rules : bl->v6_rules;
}
