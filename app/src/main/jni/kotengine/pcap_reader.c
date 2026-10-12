#include "pcap_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define CLASSIC_MAGIC_LE 0xa1b2c3d4u
#define CLASSIC_MAGIC_SWAPPED 0xd4c3b2a1u
#define PCAPNG_SHB_MAGIC 0x0A0D0D0Au
#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4Du
#define PCAPNG_EPB_TYPE 0x00000006u
#define PCAPNG_SPB_TYPE 0x00000003u /* legacy simple packet block */
#define MAX_PKT 65536

typedef enum { FMT_CLASSIC, FMT_PCAPNG } file_fmt_t;

struct netcap_pcap_reader {
    FILE *fp;
    file_fmt_t fmt;
    int swapped;        /* classic-format byte order differs from host */
    uint8_t buf[MAX_PKT];
};

static uint32_t swap32(uint32_t v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
}
netcap_pcap_reader_t *netcap_pcap_reader_open(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    uint32_t magic;
    if (fread(&magic, 4, 1, fp) != 1) { fclose(fp); return NULL; }

    netcap_pcap_reader_t *r = calloc(1, sizeof(*r));
    if (!r) { fclose(fp); return NULL; }
    r->fp = fp;

    if (magic == CLASSIC_MAGIC_LE || magic == CLASSIC_MAGIC_SWAPPED) {
        r->fmt = FMT_CLASSIC;
        r->swapped = (magic == CLASSIC_MAGIC_SWAPPED);
        /* skip rest of the 24-byte global header (already consumed 4 bytes) */
        fseek(fp, 20, SEEK_CUR);
        return r;
    }
    if (magic == PCAPNG_SHB_MAGIC) {
        r->fmt = FMT_PCAPNG;
        /* rewind and let netcap_pcap_reader_next's block scanner consume
         * the SHB like any other block (it just won't yield a packet) */
        fseek(fp, 0, SEEK_SET);
        return r;
    }

    fclose(fp);
    free(r);
    return NULL; /* unrecognized format */
}

void netcap_pcap_reader_close(netcap_pcap_reader_t *r) {
    if (!r) return;
    if (r->fp) fclose(r->fp);
    free(r);
}

static int read_classic_next(netcap_pcap_reader_t *r,
                              const uint8_t **data, uint32_t *len, uint64_t *ts_us) {
    struct { uint32_t ts_sec, ts_usec, incl_len, orig_len; } rec;
    if (fread(&rec, sizeof(rec), 1, r->fp) != 1) return 0; /* EOF */

    if (r->swapped) {
        rec.ts_sec = swap32(rec.ts_sec);
        rec.ts_usec = swap32(rec.ts_usec);
        rec.incl_len = swap32(rec.incl_len);
        rec.orig_len = swap32(rec.orig_len);
    }
    if (rec.incl_len > MAX_PKT) return -1;

    if (fread(r->buf, 1, rec.incl_len, r->fp) != rec.incl_len) return -1;
    *data = r->buf;
    *len = rec.incl_len;
    *ts_us = (uint64_t)rec.ts_sec * 1000000ull + rec.ts_usec;
    return 1;
}

/* Generic PCAPng block scanner: reads (type, block_total_length), then
 * dispatches on type. Unknown/uninteresting block types (SHB, IDB,
 * Name Resolution, Interface Statistics, ...) are skipped whole via
 * their self-reported length. Only EPB and the legacy SPB yield a
 * packet to the caller. */
static int read_pcapng_next(netcap_pcap_reader_t *r,
                             const uint8_t **data, uint32_t *len, uint64_t *ts_us) {
    for (;;) {
        uint32_t block_type, block_len;
        if (fread(&block_type, 4, 1, r->fp) != 1) return 0; /* EOF */
        if (fread(&block_len, 4, 1, r->fp) != 1) return -1;
        if (block_len < 12) return -1;

        uint32_t body_len = block_len - 12; /* minus type+len (already read) and trailing len */

        if (block_type == PCAPNG_EPB_TYPE) {
            uint32_t if_id, ts_hi, ts_lo, cap_len, orig_len;
            if (fread(&if_id, 4, 1, r->fp) != 1) return -1;
            if (fread(&ts_hi, 4, 1, r->fp) != 1) return -1;
            if (fread(&ts_lo, 4, 1, r->fp) != 1) return -1;
            if (fread(&cap_len, 4, 1, r->fp) != 1) return -1;
            if (fread(&orig_len, 4, 1, r->fp) != 1) return -1;
            (void)if_id; (void)orig_len;
            if (cap_len > MAX_PKT) return -1;
            if (fread(r->buf, 1, cap_len, r->fp) != cap_len) return -1;

            uint32_t consumed = 20 + cap_len;
            uint32_t padded = (cap_len + 3) & ~3u;
            uint32_t skip = (padded - cap_len) + (body_len - (20 + padded)) /* options, if any */;
            if (body_len >= consumed) fseek(r->fp, (long)skip, SEEK_CUR);
            fseek(r->fp, 4, SEEK_CUR); /* trailing block length */

            *data = r->buf;
            *len = cap_len;
            *ts_us = ((uint64_t)ts_hi << 32) | ts_lo;
            return 1;
        }

        if (block_type == PCAPNG_SPB_TYPE) {
            uint32_t orig_len;
            if (fread(&orig_len, 4, 1, r->fp) != 1) return -1;
            uint32_t cap_len = body_len - 4;
            if (cap_len > MAX_PKT) return -1;
            if (fread(r->buf, 1, cap_len, r->fp) != cap_len) return -1;
            uint32_t padded = (cap_len + 3) & ~3u;
            fseek(r->fp, (long)(padded - cap_len), SEEK_CUR);
            fseek(r->fp, 4, SEEK_CUR);

            *data = r->buf;
            *len = cap_len;
            *ts_us = 0; /* SPB carries no timestamp */
            return 1;
        }

        /* not a packet block: skip body + trailing length field */
        fseek(r->fp, (long)body_len, SEEK_CUR);
        fseek(r->fp, 4, SEEK_CUR);
    }
}

int netcap_pcap_reader_next(netcap_pcap_reader_t *r,
                             const uint8_t **data, uint32_t *len, uint64_t *ts_us) {
    if (!r) return -1;
    return (r->fmt == FMT_CLASSIC)
        ? read_classic_next(r, data, len, ts_us)
        : read_pcapng_next(r, data, len, ts_us);
}
