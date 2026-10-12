#include "pcapng_writer.h"
#include <stdlib.h>
#include <string.h>

#define PCAPNG_SHB_TYPE 0x0A0D0D0Au
#define PCAPNG_IDB_TYPE 0x00000001u
#define PCAPNG_EPB_TYPE 0x00000006u
#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4Du
#define LINKTYPE_RAW 101u /* raw IP, matches what a TUN fd hands us */

struct netcap_pcapng_writer {
    FILE *fp;
    uint32_t snaplen;
};

static void write_u32(FILE *fp, uint32_t v) { fwrite(&v, 4, 1, fp); }
static void write_u16(FILE *fp, uint16_t v) { fwrite(&v, 2, 1, fp); }

static uint32_t pad32(uint32_t len) { return (len + 3) & ~3u; }

netcap_pcapng_writer_t *netcap_pcapng_open(const char *path, const char *if_name,
                                            uint32_t snaplen) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return NULL;

    /* --- Section Header Block --- */
    {
        uint32_t block_len = 28; /* fixed SHB with no options */
        write_u32(fp, PCAPNG_SHB_TYPE);
        write_u32(fp, block_len);
        write_u32(fp, PCAPNG_BYTE_ORDER_MAGIC);
        write_u16(fp, 1);  /* major version */
        write_u16(fp, 0);  /* minor version */
        int64_t section_len = -1; /* unknown */
        fwrite(&section_len, 8, 1, fp);
        write_u32(fp, block_len); /* trailing length repeat */
    }

    /* --- Interface Description Block --- */
    {
        size_t name_len = if_name ? strlen(if_name) : 0;
        uint32_t opt_len = 0;
        uint32_t opt_padded = 0;
        if (name_len > 0) {
            opt_len = 4 + (uint32_t)name_len; /* option header + value */
            opt_padded = pad32(opt_len) + 4;  /* + opt_endofopt */
        }
        uint32_t block_len = 20 + opt_padded;

        write_u32(fp, PCAPNG_IDB_TYPE);
        write_u32(fp, block_len);
        write_u16(fp, LINKTYPE_RAW);
        write_u16(fp, 0); /* reserved */
        write_u32(fp, snaplen);

        if (name_len > 0) {
            write_u16(fp, 2); /* if_name option code */
            write_u16(fp, (uint16_t)name_len);
            fwrite(if_name, 1, name_len, fp);
            uint32_t pad = pad32((uint32_t)name_len) - (uint32_t)name_len;
            uint8_t zero[4] = {0};
            if (pad) fwrite(zero, 1, pad, fp);
            write_u16(fp, 0); /* opt_endofopt code */
            write_u16(fp, 0); /* opt_endofopt len */
        }
        write_u32(fp, block_len);
    }

    netcap_pcapng_writer_t *w = calloc(1, sizeof(*w));
    if (!w) { fclose(fp); return NULL; }
    w->fp = fp;
    w->snaplen = snaplen;
    return w;
}

int netcap_pcapng_write_packet(netcap_pcapng_writer_t *w, uint64_t ts_us,
                                const uint8_t *data, uint32_t data_len,
                                uint32_t orig_len) {
    if (!w || !w->fp) return -1;
    if (w->snaplen && data_len > w->snaplen) data_len = w->snaplen;

    uint32_t padded = pad32(data_len);
    uint32_t block_len = 32 + padded; /* fixed EPB fields + padded data, no options */

    write_u32(w->fp, PCAPNG_EPB_TYPE);
    write_u32(w->fp, block_len);
    write_u32(w->fp, 0); /* interface id */
    write_u32(w->fp, (uint32_t)(ts_us >> 32));
    write_u32(w->fp, (uint32_t)(ts_us & 0xFFFFFFFFu));
    write_u32(w->fp, data_len);
    write_u32(w->fp, orig_len);
    fwrite(data, 1, data_len, w->fp);
    if (padded > data_len) {
        uint8_t zero[4] = {0};
        fwrite(zero, 1, padded - data_len, w->fp);
    }
    write_u32(w->fp, block_len);
    return ferror(w->fp) ? -1 : 0;
}

int netcap_pcapng_flush(netcap_pcapng_writer_t *w) {
    if (!w || !w->fp) return -1;
    return fflush(w->fp);
}

FILE *netcap_pcapng_get_fp(netcap_pcapng_writer_t *w) {
    return w ? w->fp : NULL;
}

void netcap_pcapng_close(netcap_pcapng_writer_t *w) {
    if (!w) return;
    if (w->fp) fclose(w->fp);
    free(w);
}
