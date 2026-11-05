#define _POSIX_C_SOURCE 200809L
#include "network_policy.h"
#include "firewall.h"
#include "blacklist.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

typedef struct {
    bool enabled;
    int32_t *uids;
    size_t uid_count;
    netcap_firewall_t *domains;
    netcap_blacklist_t *ips;
} rule_set_t;

struct netcap_network_policy {
    pthread_rwlock_t lock;
    rule_set_t *sources[3];
};

static int compare_uid(const void *a, const void *b) {
    int32_t x = *(const int32_t *)a, y = *(const int32_t *)b;
    return (x > y) - (x < y);
}
static void free_rules(rule_set_t *rules) {
    if (!rules) return;
    free(rules->uids);
    netcap_firewall_destroy(rules->domains);
    netcap_blacklist_destroy(rules->ips);
    free(rules);
}
static bool valid_domain(const char *domain) {
    if (!domain || !*domain || strlen(domain) > 253) return false;
    size_t label = 0;
    char previous = 0;
    for (const unsigned char *p = (const unsigned char *)domain; *p; p++) {
        if (*p == '.') {
            if (!label || previous == '-') return false;
            label = 0;
        } else {
            if (!(isalnum(*p) || *p == '-') || (!label && *p == '-') || ++label > 63) return false;
        }
        previous = (char)*p;
    }
    return previous != '-'; /* A trailing DNS root dot is accepted. */
}
static bool add_cidr(netcap_blacklist_t *ips, const char *cidr) {
    if (!cidr || !*cidr || strlen(cidr) >= 64) return false;
    char address[64];
    strcpy(address, cidr);
    char *slash = strchr(address, '/');
    int family = strchr(address, ':') ? 6 : 4;
    long prefix = family == 6 ? 128 : 32;
    if (slash) {
        *slash++ = '\0';
        if (!*slash) return false;
        for (const char *p = slash; *p; p++) if (!isdigit((unsigned char)*p)) return false;
        char *end;
        prefix = strtol(slash, &end, 10);
        if (*end || prefix < 0 || prefix > (family == 6 ? 128 : 32)) return false;
    }
    uint8_t ip[16] = {0};
    if (inet_pton(family == 6 ? AF_INET6 : AF_INET, address, ip) != 1) return false;
    return netcap_blacklist_add(ips, ip, (uint8_t)family, (uint8_t)prefix);
}

netcap_network_policy_t *netcap_network_policy_create(void) {
    netcap_network_policy_t *p = calloc(1, sizeof(*p));
    if (p && pthread_rwlock_init(&p->lock, NULL)) { free(p); return NULL; }
    return p;
}
void netcap_network_policy_destroy(netcap_network_policy_t *p) {
    if (!p) return;
    for (int i = 0; i < 3; i++) free_rules(p->sources[i]);
    pthread_rwlock_destroy(&p->lock);
    free(p);
}
bool netcap_network_policy_replace(netcap_network_policy_t *p, int source, bool enabled,
    const int32_t *uids, size_t uid_count, const char *const *domains, size_t domain_count,
    const char *const *cidrs, size_t cidr_count) {
    if (!p || source < 0 || source > 2 || (uid_count && !uids) ||
        (domain_count && !domains) || (cidr_count && !cidrs)) return false;
    rule_set_t *next = calloc(1, sizeof(*next));
    if (!next) return false;
    next->enabled = enabled;
    next->domains = netcap_firewall_create();
    next->ips = netcap_blacklist_create();
    if (!next->domains || !next->ips) goto fail;
    if (uid_count) {
        next->uids = calloc(uid_count, sizeof(*next->uids));
        if (!next->uids) goto fail;
        for (size_t i = 0; i < uid_count; i++) {
            if (uids[i] < 0) goto fail;
            next->uids[i] = uids[i];
        }
        next->uid_count = uid_count;
        qsort(next->uids, uid_count, sizeof(*next->uids), compare_uid);
    }
    if (domain_count > 0) {
        if (!netcap_firewall_add_blocked_domains_batch(next->domains, domains, domain_count)) goto fail;
    }
    for (size_t i = 0; i < cidr_count; i++) if (!add_cidr(next->ips, cidrs[i])) goto fail;
    pthread_rwlock_wrlock(&p->lock);
    rule_set_t *old = p->sources[source];
    p->sources[source] = next;
    pthread_rwlock_unlock(&p->lock);
    free_rules(old);
    return true;
fail:
    free_rules(next);
    return false;
}
static bool matches(rule_set_t *rules, int32_t uid, const uint8_t *ip, uint8_t family, const char *domain) {
    if (!rules || !rules->enabled) return false;
    return (uid >= 0 && rules->uid_count && bsearch(&uid, rules->uids, rules->uid_count, sizeof(uid), compare_uid)) ||
        (domain && netcap_firewall_is_domain_blocked(rules->domains, domain)) ||
        (ip && (family == 4 || family == 6) && netcap_blacklist_match(rules->ips, ip, family));
}
bool netcap_network_policy_blocks(netcap_network_policy_t *p, int32_t uid,
    const uint8_t *ip, uint8_t family, const char *domain) {
    if (!p) return false;
    pthread_rwlock_rdlock(&p->lock);
    bool blocked = matches(p->sources[NETCAP_POLICY_DENY], uid, ip, family, domain) ||
        matches(p->sources[NETCAP_POLICY_FEED], uid, ip, family, domain);
    rule_set_t *allow = p->sources[NETCAP_POLICY_ALLOW];
    if (!blocked && allow && allow->enabled) blocked = !matches(allow, uid, ip, family, domain);
    pthread_rwlock_unlock(&p->lock);
    return blocked;
}
