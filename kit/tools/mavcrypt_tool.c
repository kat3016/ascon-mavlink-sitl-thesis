/*
 * mavcrypt_tool - helper for tests and microbenchmarks.
 *
 *   mavcrypt_tool bench <payload_len> <iterations> [both|seal|open]
 *       cost of protecting / verifying one MAVLink v2 frame (no network).
 *       mode "both" (default) does one seal then one open per iteration;
 *       "seal"/"open" isolate one operation, needed to separate their
 *       instruction counts under kit/bench/qemu_microbench.sh (counting the
 *       default "both" mode only gives the combined seal+open cost).
 *       Prints one line of key=value pairs (times in ns).
 *   mavcrypt_tool seal <key_hex> <prefix_hex> <counter> <role> <frame_hex>
 *   mavcrypt_tool open <key_hex> <role> <protected_hex>
 *       used by the C <-> Python cross-check (role: 0 drone, 1 gcs).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mavcrypt_core.h"

static int parse_hex(const char *s, uint8_t *out, size_t max)
{
    size_t n = strlen(s);
    if (n % 2 != 0 || n / 2 > max) {
        return -1;
    }
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

static void print_hex(const uint8_t *b, int n)
{
    for (int i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
    const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void stats(const char *name, uint64_t *v, int n)
{
    qsort(v, (size_t)n, sizeof(v[0]), cmp_u64);
    double sum = 0;
    for (int i = 0; i < n; i++) {
        sum += (double)v[i];
    }
    printf(" %s_mean=%.1f %s_median=%llu %s_p95=%llu %s_min=%llu %s_max=%llu", name, sum / n,
           name, (unsigned long long)v[n / 2], name, (unsigned long long)v[(n * 95) / 100], name,
           (unsigned long long)v[0], name, (unsigned long long)v[n - 1]);
}

/* Fixed (not scaled by iters) warm-up count: it exists only to settle caches
 * and branch predictors before the *timed* (ns) loop. If it scaled with
 * iters (as it used to: iters/10), it would silently add extra, uncancelled
 * seal/open calls to the I(20000) run of the QEMU instruction-counting
 * technique below, inflating the per-frame instruction count by roughly the
 * warm-up fraction. A fixed count is identical in every call regardless of
 * iters, so it cancels in (I(n1) - I(n0)) like the rest of the setup cost. */
#define BENCH_WARMUP 10

/* mode: 0 = seal+open (round trip), 1 = seal only, 2 = open only (of a frame
 * sealed once, outside the counted loop, so that one-time cost also cancels
 * in the I(n1) - I(n0) subtraction). Reports whichever of seal_ns/open_ns
 * the mode actually measured. */
static int bench(int plen, int iters, int mode)
{
    if (plen < 0 || plen > 255 || iters < 0) {
        fprintf(stderr, "payload_len 0..255, iterations >= 0\n");
        return 2;
    }
    static const uint8_t key32[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                       17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    static const uint8_t prefix8[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    const uint8_t *key = key32;       /* first MC_KEY_LEN bytes used */
    const uint8_t *prefix = prefix8;  /* first MC_PREFIX_LEN bytes used */
    uint8_t f[MC_MAX_PLAIN_FRAME], p[MC_MAX_FRAME], o[MC_MAX_FRAME], p_fixed[MC_MAX_FRAME];
    uint16_t n = 0;
    f[n++] = MC_STX_V2;
    f[n++] = (uint8_t)plen;
    f[n++] = 0;
    f[n++] = 0;
    f[n++] = 0;
    f[n++] = 1;
    f[n++] = 1;
    f[n++] = 0;
    f[n++] = 0;
    f[n++] = 0;
    for (int i = 0; i < plen; i++) {
        f[n++] = (uint8_t)i;
    }
    f[n++] = 0;
    f[n++] = 0;

    mc_tx_t tx;
    mc_rx_t rx;
    mc_tx_init(&tx, key, prefix, MC_ROLE_DRONE);
    mc_rx_init(&rx, key, MC_ROLE_GCS);
    /* one-time frame, sealed once regardless of mode/iters, for mode == 2 */
    const int pn_fixed = mc_seal_with_counter(&tx, 0xffffffffULL, f, n, p_fixed);
    uint64_t *ts = (iters > 0) ? malloc(sizeof(uint64_t) * (size_t)iters) : NULL;
    uint64_t *to = (iters > 0) ? malloc(sizeof(uint64_t) * (size_t)iters) : NULL;
    if (iters > 0 && (ts == NULL || to == NULL)) {
        return 3;
    }
    int pn = 0;
    for (int i = 0; i < BENCH_WARMUP; i++) { /* warm-up: fixed count, see above */
        if (mode != 2) {
            pn = mc_seal(&tx, f, n, p);
        }
        if (mode != 1) {
            rx.have_peer = 0;
            mc_open(&rx, mode == 2 ? p_fixed : p, (uint16_t)(mode == 2 ? pn_fixed : pn), o);
        }
    }
    int errors = 0;
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
        int r = 0;
        if (mode != 2) {
            t0 = now_ns();
            pn = mc_seal(&tx, f, n, p);
            t1 = now_ns();
        }
        if (mode != 1) {
            rx.have_peer = 0; /* bench the AEAD, not the replay window */
            t2 = now_ns();
            r = mc_open(&rx, mode == 2 ? p_fixed : p, (uint16_t)(mode == 2 ? pn_fixed : pn), o);
            t3 = now_ns();
            if (r != n) {
                errors++;
            }
        }
        ts[i] = t1 - t0;
        to[i] = t3 - t2;
    }
    printf("payload=%d frame=%d protected=%d mode=%s iters=%d errors=%d",
           plen, n, mode == 2 ? pn_fixed : pn, mode == 0 ? "both" : mode == 1 ? "seal" : "open",
           iters, errors);
    if (iters > 0) {
        if (mode != 2) {
            stats("seal_ns", ts, iters);
        }
        if (mode != 1) {
            stats("open_ns", to, iters);
        }
    }
    printf("\n");
    free(ts);
    free(to);
    return errors == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc >= 4 && strcmp(argv[1], "bench") == 0) {
        int mode = 0;
        if (argc >= 5) {
            if (strcmp(argv[4], "seal") == 0) {
                mode = 1;
            } else if (strcmp(argv[4], "open") == 0) {
                mode = 2;
            } else if (strcmp(argv[4], "both") != 0) {
                fprintf(stderr, "bench mode must be both|seal|open\n");
                return 2;
            }
        }
        return bench(atoi(argv[2]), atoi(argv[3]), mode);
    }
    if (argc == 7 && strcmp(argv[1], "seal") == 0) {
        uint8_t key[MC_KEY_LEN], prefix[MC_PREFIX_LEN], f[MC_MAX_PLAIN_FRAME], p[MC_MAX_FRAME];
        if (parse_hex(argv[2], key, MC_KEY_LEN) != MC_KEY_LEN
            || parse_hex(argv[3], prefix, MC_PREFIX_LEN) != MC_PREFIX_LEN) {
            return 2;
        }
        const int n = parse_hex(argv[6], f, sizeof(f));
        if (n < 0) {
            return 2;
        }
        mc_tx_t tx;
        mc_tx_init(&tx, key, prefix, (uint8_t)atoi(argv[5]));
        const int pn = mc_seal_with_counter(&tx, strtoull(argv[4], NULL, 10), f, (uint16_t)n, p);
        if (pn < 0) {
            printf("ERR %d\n", pn);
            return 1;
        }
        print_hex(p, pn);
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "open") == 0) {
        uint8_t key[MC_KEY_LEN], p[MC_MAX_FRAME], o[MC_MAX_FRAME];
        if (parse_hex(argv[2], key, MC_KEY_LEN) != MC_KEY_LEN) {
            return 2;
        }
        const int n = parse_hex(argv[4], p, sizeof(p));
        if (n < 0) {
            return 2;
        }
        mc_rx_t rx;
        mc_rx_init(&rx, key, (uint8_t)atoi(argv[3]));
        const int r = mc_open(&rx, p, (uint16_t)n, o);
        if (r < 0) {
            printf("ERR %d\n", r);
            return 1;
        }
        print_hex(o, r);
        return 0;
    }
    fprintf(stderr,
            "usage:\n  %s bench <payload_len> <iterations> [both|seal|open]\n"
            "  %s seal <key_hex> <prefix_hex> <counter> <role> <frame_hex>\n"
            "  %s open <key_hex> <role> <protected_hex>\n",
            argv[0], argv[0], argv[0]);
    return 2;
}
