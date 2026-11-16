#include "AP_MAVCrypt.h"

#if AP_MAVCRYPT_ENABLED

#include <AP_HAL/AP_HAL.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "mavcrypt_core.h"

#if __has_include("mavcrypt_key.h")
#include "mavcrypt_key.h"
#else
#error "AP_MAVCrypt: missing mavcrypt_key.h - run kit/gen_key.py and kit/drone/apply_mavcrypt.py"
#endif

extern const AP_HAL::HAL& hal;

static_assert(MAVCRYPT_TX_OVERHEAD == MC_OVERHEAD, "overhead mismatch");
static_assert(MAVCRYPT_MAX_PLAIN == MC_MAX_PLAIN_FRAME, "frame size mismatch");

namespace {

struct ChanState {
    bool initialised;
    bool capturing;
    bool overflow;
    uint16_t len;
    uint8_t frame[MC_MAX_PLAIN_FRAME];
    uint8_t out[MC_MAX_FRAME];
    mc_tx_t tx;
    mc_rx_t rx;
};

ChanState state[MAVCRYPT_MAX_CHANS];

// 8 random bytes per channel and boot: the nonce prefix
void random_prefix(uint8_t prefix[MC_PREFIX_LEN])
{
    if (hal.util != nullptr && hal.util->get_random_vals(prefix, MC_PREFIX_LEN)) {
        return;
    }
    const int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        const ssize_t n = read(fd, prefix, MC_PREFIX_LEN);
        close(fd);
        if (n == MC_PREFIX_LEN) {
            return;
        }
    }
    // last resort, should never happen on Linux/SITL
    const uint64_t t = AP_HAL::micros64();
    for (uint8_t i = 0; i < MC_PREFIX_LEN; i++) {
        prefix[i] = uint8_t(t >> (8 * i));
    }
}

ChanState *get_state(uint8_t chan)
{
    if (chan >= MAVCRYPT_MAX_CHANS) {
        return nullptr;
    }
    ChanState &s = state[chan];
    if (!s.initialised) {
        uint8_t prefix[MC_PREFIX_LEN];
        random_prefix(prefix);
        mc_tx_init(&s.tx, MAVCRYPT_KEY, prefix, MC_ROLE_DRONE);
        mc_rx_init(&s.rx, MAVCRYPT_KEY, MC_ROLE_DRONE);
        s.initialised = true;
    }
    return &s;
}

#if MAVCRYPT_STATS_EVERY > 0
struct Stats {
    uint32_t frames;
    uint64_t sum_ns;
    uint64_t min_ns;
    uint64_t max_ns;
    uint64_t bytes;
};
Stats stats[2]; // 0 = tx (encrypt), 1 = rx (decrypt)
bool stats_header_done;

uint64_t now_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ULL + uint64_t(ts.tv_nsec);
}

void stats_add(uint8_t dir, uint64_t ns, uint16_t bytes, const mc_rx_t *rx)
{
    Stats &st = stats[dir];
    if (st.frames == 0 || ns < st.min_ns) {
        st.min_ns = ns;
    }
    if (ns > st.max_ns) {
        st.max_ns = ns;
    }
    st.frames++;
    st.sum_ns += ns;
    st.bytes += bytes;
    if (st.frames < MAVCRYPT_STATS_EVERY) {
        return;
    }
    FILE *f = fopen(MAVCRYPT_STATS_PATH, "a");
    if (f != nullptr) {
        if (!stats_header_done) {
            fprintf(f, "t_ms,dir,frames,mean_ns,min_ns,max_ns,mean_bytes,auth_fail,replay\n");
            stats_header_done = true;
        }
        fprintf(f, "%lu,%s,%lu,%.1f,%llu,%llu,%.2f,%lu,%lu\n",
                (unsigned long)AP_HAL::millis(), dir == 0 ? "tx" : "rx",
                (unsigned long)st.frames, double(st.sum_ns) / st.frames,
                (unsigned long long)st.min_ns, (unsigned long long)st.max_ns,
                double(st.bytes) / st.frames,
                (unsigned long)(rx ? rx->auth_fail : 0), (unsigned long)(rx ? rx->replay : 0));
        fclose(f);
    }
    memset(&st, 0, sizeof(st));
}
#endif  // MAVCRYPT_STATS_EVERY

}  // namespace

void mavcrypt_tx_begin(uint8_t chan)
{
    ChanState *s = get_state(chan);
    if (s == nullptr) {
        return;
    }
    s->capturing = true;
    s->overflow = false;
    s->len = 0;
}

bool mavcrypt_tx_capturing(uint8_t chan)
{
    return chan < MAVCRYPT_MAX_CHANS && state[chan].capturing;
}

void mavcrypt_tx_append(uint8_t chan, const uint8_t *buf, uint16_t len)
{
    ChanState &s = state[chan];
    if (s.overflow || s.len + len > MC_MAX_PLAIN_FRAME) {
        s.overflow = true;
        return;
    }
    memcpy(&s.frame[s.len], buf, len);
    s.len += len;
}

uint16_t mavcrypt_tx_end(uint8_t chan, const uint8_t **out)
{
    if (chan >= MAVCRYPT_MAX_CHANS) {
        return 0;
    }
    ChanState &s = state[chan];
    if (!s.capturing) {
        return 0;
    }
    s.capturing = false;
    if (s.overflow || s.len == 0) {
        return 0;
    }
#if MAVCRYPT_STATS_EVERY > 0
    const uint64_t t0 = now_ns();
#endif
    const int n = mc_seal(&s.tx, s.frame, s.len, s.out);
#if MAVCRYPT_STATS_EVERY > 0
    stats_add(0, now_ns() - t0, s.len, nullptr);
#endif
    if (n <= 0) {
        return 0;
    }
    *out = s.out;
    return uint16_t(n);
}

uint16_t mavcrypt_rx_push(uint8_t chan, uint8_t c, uint8_t *out)
{
    ChanState *s = get_state(chan);
    if (s == nullptr) {
        return 0;
    }
#if MAVCRYPT_STATS_EVERY > 0
    const uint64_t t0 = now_ns();
    const uint16_t n = mc_rx_push(&s->rx, c, out);
    if (n > 0) {
        stats_add(1, now_ns() - t0, n, &s->rx);
    }
    return n;
#else
    return mc_rx_push(&s->rx, c, out);
#endif
}

uint16_t mavcrypt_rx_poll(uint8_t chan, uint8_t *out)
{
    if (chan >= MAVCRYPT_MAX_CHANS) {
        return 0;
    }
    return mc_rx_poll(&state[chan].rx, out);
}

#endif  // AP_MAVCRYPT_ENABLED
