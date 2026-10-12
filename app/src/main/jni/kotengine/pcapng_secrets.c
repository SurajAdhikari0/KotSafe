#define _POSIX_C_SOURCE 200809L
#include "pcapng_secrets.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>

typedef struct {
    uint32_t secrets_type;
    uint8_t *data;
    uint32_t len;
} secret_entry_t;

struct netcap_secrets_store {
    pthread_mutex_t lock;
    secret_entry_t *entries;
    size_t count;
    size_t capacity;
};

static uint32_t pad32(uint32_t len) {
    return (len + 3) & ~3u;
}

netcap_secrets_store_t *netcap_secrets_create(size_t max_entries) {
    netcap_secrets_store_t *store = calloc(1, sizeof(*store));
    if (!store) return NULL;

    pthread_mutex_init(&store->lock, NULL);
    store->capacity = max_entries > 0 ? max_entries : 256;
    store->entries = calloc(store->capacity, sizeof(secret_entry_t));
    if (!store->entries) {
        pthread_mutex_destroy(&store->lock);
        free(store);
        return NULL;
    }
    return store;
}

void netcap_secrets_destroy(netcap_secrets_store_t *store) {
    if (!store) return;
    pthread_mutex_lock(&store->lock);
    for (size_t i = 0; i < store->count; i++) {
        free(store->entries[i].data);
    }
    free(store->entries);
    pthread_mutex_unlock(&store->lock);
    pthread_mutex_destroy(&store->lock);
    free(store);
}

size_t netcap_pcapng_build_dsb(uint32_t secrets_type, const uint8_t *data, uint32_t data_len,
                               uint8_t *out_buf, size_t out_cap) {
    uint32_t padded_len = pad32(data_len);
    uint32_t block_len = 20 + padded_len;

    if (!out_buf || out_cap < block_len) {
        return block_len;
    }

    uint32_t block_type = PCAPNG_DSB_TYPE;
    memcpy(out_buf, &block_type, 4);
    memcpy(out_buf + 4, &block_len, 4);
    memcpy(out_buf + 8, &secrets_type, 4);
    memcpy(out_buf + 12, &data_len, 4);
    if (data_len > 0 && data) {
        memcpy(out_buf + 16, data, data_len);
    }
    if (padded_len > data_len) {
        memset(out_buf + 16 + data_len, 0, padded_len - data_len);
    }
    memcpy(out_buf + 16 + padded_len, &block_len, 4);

    return block_len;
}

int netcap_pcapng_write_dsb_file(FILE *fp, uint32_t secrets_type, const uint8_t *data, uint32_t data_len) {
    if (!fp) return -1;
    uint32_t padded_len = pad32(data_len);
    uint32_t block_len = 20 + padded_len;

    uint32_t block_type = PCAPNG_DSB_TYPE;
    if (fwrite(&block_type, 4, 1, fp) != 1) return -1;
    if (fwrite(&block_len, 4, 1, fp) != 1) return -1;
    if (fwrite(&secrets_type, 4, 1, fp) != 1) return -1;
    if (fwrite(&data_len, 4, 1, fp) != 1) return -1;
    if (data_len > 0 && data) {
        if (fwrite(data, 1, data_len, fp) != data_len) return -1;
    }
    if (padded_len > data_len) {
        uint8_t zero[4] = {0};
        if (fwrite(zero, 1, padded_len - data_len, fp) != (padded_len - data_len)) return -1;
    }
    if (fwrite(&block_len, 4, 1, fp) != 1) return -1;
    return 0;
}

int netcap_secrets_add_tls_key(netcap_secrets_store_t *store, const char *keylog_line) {
    if (!store || !keylog_line) return -1;

    size_t line_len = strlen(keylog_line);
    if (line_len == 0) return 0;

    /* Ensure string ends with newline as per SSLKEYLOGFILE spec */
    int needs_nl = (keylog_line[line_len - 1] != '\n');
    size_t alloc_len = line_len + (needs_nl ? 1 : 0);

    uint8_t *buf = malloc(alloc_len);
    if (!buf) return -1;
    memcpy(buf, keylog_line, line_len);
    if (needs_nl) buf[line_len] = '\n';

    pthread_mutex_lock(&store->lock);

    /* If capacity reached, remove oldest entry (ring-buffer style or shift) */
    if (store->count >= store->capacity) {
        free(store->entries[0].data);
        memmove(&store->entries[0], &store->entries[1], (store->count - 1) * sizeof(secret_entry_t));
        store->count--;
    }

    store->entries[store->count].secrets_type = PCAPNG_DSB_SECRETS_TLS;
    store->entries[store->count].data = buf;
    store->entries[store->count].len = (uint32_t)alloc_len;
    store->count++;

    pthread_mutex_unlock(&store->lock);
    return 0;
}

int netcap_secrets_dump_all_to_fd(netcap_secrets_store_t *store, int sock_fd) {
    if (!store || sock_fd < 0) return -1;

    pthread_mutex_lock(&store->lock);
    uint8_t tmp_buf[4096];
    for (size_t i = 0; i < store->count; i++) {
        secret_entry_t *e = &store->entries[i];
        size_t block_len = netcap_pcapng_build_dsb(e->secrets_type, e->data, e->len, tmp_buf, sizeof(tmp_buf));
        if (block_len <= sizeof(tmp_buf)) {
            send(sock_fd, tmp_buf, block_len, MSG_NOSIGNAL);
        } else {
            uint8_t *big_buf = malloc(block_len);
            if (big_buf) {
                netcap_pcapng_build_dsb(e->secrets_type, e->data, e->len, big_buf, block_len);
                send(sock_fd, big_buf, block_len, MSG_NOSIGNAL);
                free(big_buf);
            }
        }
    }
    pthread_mutex_unlock(&store->lock);
    return 0;
}

int netcap_secrets_dump_all_to_file(netcap_secrets_store_t *store, FILE *fp) {
    if (!store || !fp) return -1;

    pthread_mutex_lock(&store->lock);
    for (size_t i = 0; i < store->count; i++) {
        secret_entry_t *e = &store->entries[i];
        netcap_pcapng_write_dsb_file(fp, e->secrets_type, e->data, e->len);
    }
    pthread_mutex_unlock(&store->lock);
    return 0;
}
