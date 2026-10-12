#define _POSIX_C_SOURCE 200809L
#include "firewall.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#define INITIAL_BUCKETS 1024

typedef struct domain_node {
    char *domain;
    struct domain_node *next;
} domain_node_t;

struct netcap_firewall {
    int32_t *blocked_uids;
    uint32_t blocked_uids_count;

    domain_node_t **domain_buckets;
    uint32_t domain_bucket_mask;
    uint32_t domain_count;

    pthread_mutex_t lock;
};

static uint32_t hash_str(const char *str) {
    uint32_t h = 2166136261u;
    while (*str) {
        h ^= (uint8_t)tolower((unsigned char)*str);
        h *= 16777619u;
        str++;
    }
    return h;
}

static int uid_cmp(const void *a, const void *b) {
    int32_t ia = *(const int32_t *)a;
    int32_t ib = *(const int32_t *)b;
    return (ia > ib) - (ia < ib);
}

netcap_firewall_t *netcap_firewall_create(void) {
    netcap_firewall_t *fw = calloc(1, sizeof(*fw));
    if (!fw) return NULL;

    fw->domain_buckets = calloc(INITIAL_BUCKETS, sizeof(domain_node_t *));
    if (!fw->domain_buckets) {
        free(fw);
        return NULL;
    }
    fw->domain_bucket_mask = INITIAL_BUCKETS - 1;
    pthread_mutex_init(&fw->lock, NULL);
    return fw;
}

void netcap_firewall_destroy(netcap_firewall_t *fw) {
    if (!fw) return;
    pthread_mutex_lock(&fw->lock);

    free(fw->blocked_uids);
    fw->blocked_uids = NULL;

    for (uint32_t i = 0; i <= fw->domain_bucket_mask; i++) {
        domain_node_t *node = fw->domain_buckets[i];
        while (node) {
            domain_node_t *next = node->next;
            free(node->domain);
            free(node);
            node = next;
        }
    }
    free(fw->domain_buckets);

    pthread_mutex_unlock(&fw->lock);
    pthread_mutex_destroy(&fw->lock);
    free(fw);
}

void netcap_firewall_set_blocked_uids(netcap_firewall_t *fw, const int32_t *uids, uint32_t count) {
    if (!fw) return;
    pthread_mutex_lock(&fw->lock);

    free(fw->blocked_uids);
    fw->blocked_uids = NULL;
    fw->blocked_uids_count = 0;

    if (uids && count > 0) {
        fw->blocked_uids = malloc(count * sizeof(int32_t));
        if (fw->blocked_uids) {
            memcpy(fw->blocked_uids, uids, count * sizeof(int32_t));
            fw->blocked_uids_count = count;
            qsort(fw->blocked_uids, count, sizeof(int32_t), uid_cmp);
        }
    }

    pthread_mutex_unlock(&fw->lock);
}

bool netcap_firewall_is_uid_blocked(const netcap_firewall_t *fw, int32_t uid) {
    if (!fw || uid < 0 || fw->blocked_uids_count == 0 || !fw->blocked_uids) return false;

    /* Binary search */
    const int32_t *res = bsearch(&uid, fw->blocked_uids, fw->blocked_uids_count, sizeof(int32_t), uid_cmp);
    return (res != NULL);
}

static char *normalize_domain(const char *domain) {
    if (!domain) return NULL;
    size_t len = strlen(domain);
    while (len > 0 && domain[len - 1] == '.') len--;
    if (len == 0) return NULL;

    char *norm = malloc(len + 1);
    if (!norm) return NULL;
    for (size_t i = 0; i < len; i++) {
        norm[i] = (char)tolower((unsigned char)domain[i]);
    }
    norm[len] = '\0';
    return norm;
}

void netcap_firewall_add_blocked_domain(netcap_firewall_t *fw, const char *domain) {
    if (!fw || !domain || domain[0] == '\0') return;

    char *norm = normalize_domain(domain);
    if (!norm) return;

    uint32_t h = hash_str(norm);

    pthread_mutex_lock(&fw->lock);
    uint32_t b = h & fw->domain_bucket_mask;

    /* Check duplicate */
    domain_node_t *node = fw->domain_buckets[b];
    while (node) {
        if (strcmp(node->domain, norm) == 0) {
            free(norm);
            pthread_mutex_unlock(&fw->lock);
            return;
        }
        node = node->next;
    }

    domain_node_t *new_node = malloc(sizeof(*new_node));
    if (new_node) {
        new_node->domain = norm;
        new_node->next = fw->domain_buckets[b];
        fw->domain_buckets[b] = new_node;
        fw->domain_count++;
    } else {
        free(norm);
    }

    pthread_mutex_unlock(&fw->lock);
}

void netcap_firewall_remove_blocked_domain(netcap_firewall_t *fw, const char *domain) {
    if (!fw || !domain) return;
    char *norm = normalize_domain(domain);
    if (!norm) return;

    uint32_t h = hash_str(norm);
    pthread_mutex_lock(&fw->lock);
    uint32_t b = h & fw->domain_bucket_mask;

    domain_node_t *node = fw->domain_buckets[b];
    domain_node_t *prev = NULL;

    while (node) {
        if (strcmp(node->domain, norm) == 0) {
            if (prev) prev->next = node->next;
            else fw->domain_buckets[b] = node->next;
            free(node->domain);
            free(node);
            fw->domain_count--;
            break;
        }
        prev = node;
        node = node->next;
    }

    pthread_mutex_unlock(&fw->lock);
    free(norm);
}

void netcap_firewall_clear_blocked_domains(netcap_firewall_t *fw) {
    if (!fw) return;
    pthread_mutex_lock(&fw->lock);

    for (uint32_t i = 0; i <= fw->domain_bucket_mask; i++) {
        domain_node_t *node = fw->domain_buckets[i];
        while (node) {
            domain_node_t *next = node->next;
            free(node->domain);
            free(node);
            node = next;
        }
        fw->domain_buckets[i] = NULL;
    }
    fw->domain_count = 0;

    pthread_mutex_unlock(&fw->lock);
}

bool netcap_firewall_is_domain_blocked(const netcap_firewall_t *fw, const char *domain) {
    if (!fw || !domain || domain[0] == '\0' || fw->domain_count == 0) return false;

    char *norm = normalize_domain(domain);
    if (!norm) return false;

    bool blocked = false;
    const char *curr = norm;

    pthread_mutex_lock((pthread_mutex_t *)&fw->lock);

    /*
     * Check exact match first, then parent domain suffixes:
     * e.g. "ad.tracker.xyz" -> checks "ad.tracker.xyz", then "tracker.xyz"
     */
    while (curr && *curr) {
        uint32_t h = hash_str(curr);
        uint32_t b = h & fw->domain_bucket_mask;
        domain_node_t *node = fw->domain_buckets[b];
        while (node) {
            if (strcmp(node->domain, curr) == 0) {
                blocked = true;
                break;
            }
            node = node->next;
        }
        if (blocked) break;

        /* Move to next label after dot */
        const char *next_dot = strchr(curr, '.');
        if (next_dot && *(next_dot + 1)) {
            curr = next_dot + 1;
        } else {
            break;
        }
    }

    pthread_mutex_unlock((pthread_mutex_t *)&fw->lock);
    free(norm);
    return blocked;
}

uint32_t netcap_firewall_blocked_domains_count(const netcap_firewall_t *fw) {
    if (!fw) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&fw->lock);
    uint32_t c = fw->domain_count;
    pthread_mutex_unlock((pthread_mutex_t *)&fw->lock);
    return c;
}
