/*
 * dtls_tunnel - carries UDP datagrams inside a DTLS 1.3 session (RFC 9147)
 * using wolfSSL. It implements the "dtls" treatment of the thesis: the MAVLink
 * firmware is the unmodified "plain" build, and protection is added around
 * it, not inside it.
 *
 *   UAV namespace            veth link (NetEm)            root namespace
 *   SITL --UDP--> [server] <==== DTLS 1.3 ====> [client] --UDP--> secure_proxy
 *
 * One datagram in on the clear side becomes exactly one DTLS record (one
 * datagram) on the protected side and vice versa, so MAVLink frame boundaries
 * produced by the SITL packetiser are preserved and the per-datagram byte
 * overhead is the DTLS 1.3 record overhead alone (RFC 9147 Section 4: 1 flag
 * byte + 1 or 2 sequence bytes + 0 or 2 length bytes + 1 inner content type
 * byte + 16-byte AEAD tag = 19 to 22 bytes).
 *
 *   dtls_tunnel --role server --dtls-addr 10.10.0.2:5762 \
 *               --plain-bind 127.0.0.1:14551 --cert uav.pem --key uav.key
 *   dtls_tunnel --role client --dtls-addr 10.10.0.2:5762 \
 *               --plain-bind <host>:0 --plain-peer <host>:14550 \
 *               --ca uav.pem --name uav.mavcrypt.local
 *
 * --dtls-addr   server: address to bind; client: server to connect to
 * --plain-bind  local address of the clear-text UDP socket
 * --plain-peer  where decrypted datagrams go; if omitted, the source of the
 *               last datagram received on the clear side is used (that is how
 *               the server side finds the SITL's ephemeral UDP port)
 * --stats FILE  key=value counters written on exit
 *
 * Only TLS_AES_128_GCM_SHA256 is offered (same AEAD as the "aesgcm"
 * treatment, 128-bit key) and only DTLS 1.3; the tunnel exits if the
 * negotiated version or suite differs. Session tickets are disabled so that
 * no post-handshake message needs retransmission during measurement.
 *
 * Not implemented, on purpose: DTLS cookie exchange (address validation
 * against spoofed senders) and Connection ID. The testbed has exactly one
 * peer on an isolated virtual link, so neither changes the measurement.
 */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SUITE "TLS13-AES128-GCM-SHA256"
#define WANT_SUITE "TLS_AES_128_GCM_SHA256"
#define BUF_SZ 2048
#define HANDSHAKE_DEADLINE_S 30

static volatile sig_atomic_t g_run = 1;

static void on_signal(int s)
{
    (void)s;
    g_run = 0;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int parse_addr(const char *s, struct sockaddr_in *sa)
{
    char host[64];
    const char *colon = strrchr(s, ':');
    if (colon == NULL || (size_t)(colon - s) >= sizeof(host)) {
        return -1;
    }
    memcpy(host, s, (size_t)(colon - s));
    host[colon - s] = '\0';
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)atoi(colon + 1));
    return inet_pton(AF_INET, host, &sa->sin_addr) == 1 ? 0 : -1;
}

static struct {
    uint64_t plain_to_dtls_dgrams, plain_to_dtls_bytes;
    uint64_t dtls_to_plain_dgrams, dtls_to_plain_bytes;
    uint64_t write_dropped, write_errors, read_errors, no_peer_drops, timeouts;
} st;

static void log_wolf_err(WOLFSSL *ssl, int ret, const char *what)
{
    char msg[96];
    const int err = wolfSSL_get_error(ssl, ret);
    wolfSSL_ERR_error_string((unsigned long)err, msg);
    fprintf(stderr, "dtls_tunnel: %s failed: %s (%d)\n", what, msg, err);
}

static int timeout_ms(WOLFSSL *ssl)
{
    int ms = wolfSSL_dtls_get_current_timeout(ssl) * 1000;
    if (ms < 200 || ms > 5000) {
        ms = 1000; /* RFC 9147 Section 5.8.2: initial timer 1000 ms */
    }
    return ms;
}

static void dtls_to_plain(WOLFSSL *ssl, int plain_fd, const struct sockaddr_in *peer, int have_peer);

/* non-blocking handshake, retransmitting on timeout like wolfSSL's own
 * examples (examples/{client,server}: NonBlockingSSL_{Connect,Accept}).
 * In DTLS 1.3 the client has sent its Finished but is still waiting for the
 * server's ACK when the server, already done, starts sending application
 * data: wolfSSL then reports APP_DATA_READY from connect/accept. That is not
 * an error; the data must be read (it is real telemetry, so it is forwarded)
 * and the handshake call repeated until the ACK arrives. */
static int handshake(WOLFSSL *ssl, int fd, int is_server, int plain_fd,
                     const struct sockaddr_in *peer, int have_peer)
{
    const uint64_t deadline = now_ns() + (uint64_t)HANDSHAKE_DEADLINE_S * 1000000000ull;
    for (;;) {
        const int ret = is_server ? wolfSSL_accept(ssl) : wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS) {
            return 0;
        }
        const int err = wolfSSL_get_error(ssl, ret);
        if (err == APP_DATA_READY) {
            dtls_to_plain(ssl, plain_fd, peer, have_peer);
            continue;
        }
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            log_wolf_err(ssl, ret, is_server ? "accept" : "connect");
            return -1;
        }
        if (!g_run || now_ns() > deadline) {
            fprintf(stderr, "dtls_tunnel: handshake did not complete in %d s\n",
                    HANDSHAKE_DEADLINE_S);
            return -1;
        }
        struct pollfd p = {fd, (short)(err == WOLFSSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN), 0};
        const int r = poll(&p, 1, timeout_ms(ssl));
        if (r == 0) {
            if (wolfSSL_dtls_got_timeout(ssl) != WOLFSSL_SUCCESS) {
                log_wolf_err(ssl, WOLFSSL_FATAL_ERROR, "retransmission");
                return -1;
            }
        } else if (r < 0 && errno != EINTR) {
            perror("dtls_tunnel: poll");
            return -1;
        }
    }
}

static void dtls_to_plain(WOLFSSL *ssl, int plain_fd, const struct sockaddr_in *peer, int have_peer)
{
    unsigned char buf[BUF_SZ];
    for (int i = 0; i < 64 && g_run; i++) {
        const int n = wolfSSL_read(ssl, buf, sizeof(buf));
        if (n > 0) {
            if (!have_peer) {
                st.no_peer_drops++;
                continue;
            }
            sendto(plain_fd, buf, (size_t)n, 0, (const struct sockaddr *)peer, sizeof(*peer));
            st.dtls_to_plain_dgrams++;
            st.dtls_to_plain_bytes += (uint64_t)n;
            continue;
        }
        const int err = wolfSSL_get_error(ssl, n);
        if (err == APP_DATA_READY) {
            /* Not an error: while the client still waits for the ACK of its
             * Finished (that ACK can be lost on a lossy link) wolfSSL hands the
             * decrypted record over in two steps, reporting APP_DATA_READY first
             * and returning the data on the next read. Leaving the loop here
             * would hold the datagram back until the next one arrives. */
            continue;
        }
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            return; /* nothing left, or the datagram was a handshake/ACK/dropped record */
        }
        if (err == WOLFSSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "dtls_tunnel: peer sent close_notify\n");
            g_run = 0;
            return;
        }
        st.read_errors++;
        log_wolf_err(ssl, n, "read");
        return;
    }
}

static void plain_to_dtls(WOLFSSL *ssl, int plain_fd, struct sockaddr_in *peer, int *have_peer,
                          int peer_fixed)
{
    unsigned char buf[BUF_SZ];
    for (int i = 0; i < 64; i++) {
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        const ssize_t n = recvfrom(plain_fd, buf, sizeof(buf), MSG_DONTWAIT,
                                   (struct sockaddr *)&src, &sl);
        if (n < 0) {
            return;
        }
        if (!peer_fixed) {
            *peer = src;
            *have_peer = 1;
        }
        const int w = wolfSSL_write(ssl, buf, (int)n);
        if (w == (int)n) {
            st.plain_to_dtls_dgrams++;
            st.plain_to_dtls_bytes += (uint64_t)n;
            continue;
        }
        const int err = wolfSSL_get_error(ssl, w);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            st.write_dropped++; /* datagram service: drop, like a lossy link would */
        } else {
            st.write_errors++;
            log_wolf_err(ssl, w, "write");
        }
    }
}

static void write_stats(const char *path, double handshake_ms, const char *version,
                        const char *suite)
{
    FILE *f = path ? fopen(path, "w") : stderr;
    if (f == NULL) {
        return;
    }
    fprintf(f,
            "handshake_ms=%.3f\nversion=%s\nsuite=%s\n"
            "plain_to_dtls_dgrams=%llu\nplain_to_dtls_bytes=%llu\n"
            "dtls_to_plain_dgrams=%llu\ndtls_to_plain_bytes=%llu\n"
            "write_dropped=%llu\nwrite_errors=%llu\nread_errors=%llu\n"
            "no_peer_drops=%llu\ntimeouts=%llu\n",
            handshake_ms, version, suite, (unsigned long long)st.plain_to_dtls_dgrams,
            (unsigned long long)st.plain_to_dtls_bytes, (unsigned long long)st.dtls_to_plain_dgrams,
            (unsigned long long)st.dtls_to_plain_bytes, (unsigned long long)st.write_dropped,
            (unsigned long long)st.write_errors, (unsigned long long)st.read_errors,
            (unsigned long long)st.no_peer_drops, (unsigned long long)st.timeouts);
    if (path) {
        fclose(f);
    }
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --role server|client --dtls-addr ip:port --plain-bind ip:port\n"
            "          [--plain-peer ip:port] [--stats file]\n"
            "          server: --cert pem --key pem     client: --ca pem [--name host]\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *role = NULL, *dtls_addr = NULL, *plain_bind = NULL, *plain_peer = NULL;
    const char *cert = NULL, *key = NULL, *ca = NULL, *name = NULL, *stats = NULL;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--role")) role = argv[i + 1];
        else if (!strcmp(argv[i], "--dtls-addr")) dtls_addr = argv[i + 1];
        else if (!strcmp(argv[i], "--plain-bind")) plain_bind = argv[i + 1];
        else if (!strcmp(argv[i], "--plain-peer")) plain_peer = argv[i + 1];
        else if (!strcmp(argv[i], "--cert")) cert = argv[i + 1];
        else if (!strcmp(argv[i], "--key")) key = argv[i + 1];
        else if (!strcmp(argv[i], "--ca")) ca = argv[i + 1];
        else if (!strcmp(argv[i], "--name")) name = argv[i + 1];
        else if (!strcmp(argv[i], "--stats")) stats = argv[i + 1];
        else { usage(argv[0]); return 2; }
    }
    const int is_server = role && !strcmp(role, "server");
    if (!role || (!is_server && strcmp(role, "client")) || !dtls_addr || !plain_bind ||
        (is_server && (!cert || !key)) || (!is_server && !ca)) {
        usage(argv[0]);
        return 2;
    }

    struct sockaddr_in dtls_sa, plain_sa, peer_sa;
    int have_peer = 0;
    memset(&peer_sa, 0, sizeof(peer_sa));
    if (parse_addr(dtls_addr, &dtls_sa) || parse_addr(plain_bind, &plain_sa)) {
        fprintf(stderr, "dtls_tunnel: bad address\n");
        return 2;
    }
    const int peer_fixed = plain_peer != NULL;
    if (peer_fixed) {
        if (parse_addr(plain_peer, &peer_sa)) {
            fprintf(stderr, "dtls_tunnel: bad --plain-peer\n");
            return 2;
        }
        have_peer = 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    const int plain_fd = socket(AF_INET, SOCK_DGRAM, 0);
    const int dtls_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (plain_fd < 0 || dtls_fd < 0 ||
        bind(plain_fd, (struct sockaddr *)&plain_sa, sizeof(plain_sa)) < 0) {
        perror("dtls_tunnel: socket/bind (clear side)");
        return 1;
    }

    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(is_server ? wolfDTLSv1_3_server_method()
                                                 : wolfDTLSv1_3_client_method());
    if (ctx == NULL || wolfSSL_CTX_set_cipher_list(ctx, SUITE) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "dtls_tunnel: cannot create a DTLS 1.3 context with suite %s "
                        "(was wolfSSL built with --enable-dtls13?)\n", SUITE);
        return 1;
    }
    if (is_server) {
        if (wolfSSL_CTX_use_certificate_file(ctx, cert, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_use_PrivateKey_file(ctx, key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "dtls_tunnel: cannot load %s / %s\n", cert, key);
            return 1;
        }
#ifdef HAVE_SESSION_TICKET
        wolfSSL_CTX_no_ticket_TLSv13(ctx);
#endif
    } else {
        if (wolfSSL_CTX_load_verify_locations(ctx, ca, NULL) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "dtls_tunnel: cannot load CA %s\n", ca);
            return 1;
        }
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "dtls_tunnel: wolfSSL_new failed\n");
        return 1;
    }
    if (wolfSSL_set_fd(ssl, dtls_fd) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "dtls_tunnel: wolfSSL_set_fd failed\n");
        return 1;
    }
#ifdef HAVE_SUPPORTED_CURVES
    {
        /* one key-exchange group, P-256 (same curve as the certificate), so
         * the handshake does not depend on wolfSSL's default group list
         * (which includes post-quantum hybrids and fragments the ClientHello) */
        int groups[1] = {WOLFSSL_ECC_SECP256R1};
        if (wolfSSL_set_groups(ssl, groups, 1) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "dtls_tunnel: cannot restrict the key-exchange group\n");
            return 1;
        }
    }
#endif

    if (is_server) {
        int one = 1;
        setsockopt(dtls_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(dtls_fd, (struct sockaddr *)&dtls_sa, sizeof(dtls_sa)) < 0) {
            perror("dtls_tunnel: bind (DTLS side)");
            return 1;
        }
        /* peek the first datagram (a ClientHello) to learn the peer's address,
         * as wolfSSL's own example server does */
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        unsigned char b[BUF_SZ];
        fprintf(stderr, "dtls_tunnel: server waiting on %s\n", dtls_addr);
        for (;;) {
            struct pollfd p = {dtls_fd, POLLIN, 0};
            if (poll(&p, 1, 500) > 0) {
                cl = sizeof(cli);
                const ssize_t n = recvfrom(dtls_fd, b, sizeof(b), MSG_PEEK,
                                           (struct sockaddr *)&cli, &cl);
                if (n > 0 && b[0] == 0x16) { /* handshake record: the ClientHello */
                    break;
                }
                if (n > 0) { /* stray datagram: discard */
                    recvfrom(dtls_fd, b, sizeof(b), 0, (struct sockaddr *)&cli, &cl);
                }
            }
            if (!g_run) {
                return 1;
            }
        }
        wolfSSL_dtls_set_peer(ssl, &cli, cl);
    } else {
        if (connect(dtls_fd, (struct sockaddr *)&dtls_sa, sizeof(dtls_sa)) < 0) {
            perror("dtls_tunnel: connect (DTLS side)");
            return 1;
        }
        if (name != NULL && wolfSSL_check_domain_name(ssl, name) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "dtls_tunnel: cannot set expected host name\n");
            return 1;
        }
    }

    fcntl(dtls_fd, F_SETFL, fcntl(dtls_fd, F_GETFL, 0) | O_NONBLOCK);
    wolfSSL_dtls_set_using_nonblock(ssl, 1);

    const uint64_t t0 = now_ns();
    if (handshake(ssl, dtls_fd, is_server, plain_fd, &peer_sa, have_peer) != 0) {
        return 1;
    }
    const double handshake_ms = (double)(now_ns() - t0) / 1e6;
    const char *version = wolfSSL_get_version(ssl);
    const char *suite = wolfSSL_get_cipher(ssl);
    fprintf(stderr, "dtls_tunnel: %s handshake_ms=%.3f version=%s suite=%s\n",
            role, handshake_ms, version, suite);
    if (strcmp(version, "DTLSv1.3") != 0 || strcmp(suite, WANT_SUITE) != 0) {
        fprintf(stderr, "dtls_tunnel: refusing to continue: expected DTLSv1.3 / %s\n", WANT_SUITE);
        return 3;
    }

    struct pollfd fds[2] = {{dtls_fd, POLLIN, 0}, {plain_fd, POLLIN, 0}};
    while (g_run) {
        const int r = poll(fds, 2, timeout_ms(ssl));
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("dtls_tunnel: poll");
            break;
        }
        if (r == 0) {
            st.timeouts++;
            wolfSSL_dtls_got_timeout(ssl); /* retransmit unacknowledged records, if any */
            continue;
        }
        if (fds[0].revents & POLLIN) {
            dtls_to_plain(ssl, plain_fd, &peer_sa, have_peer);
        }
        if (fds[1].revents & POLLIN) {
            plain_to_dtls(ssl, plain_fd, &peer_sa, &have_peer, peer_fixed);
        }
    }

    wolfSSL_shutdown(ssl);
    write_stats(stats, handshake_ms, version, suite);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
