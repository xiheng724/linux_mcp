/*
 * native_echo: minimal native UDS backend for binary-replacement testing.
 *
 * Reads `--endpoint <path>` and exposes one JSON-RPC operation ("echo")
 * over the same 4-byte-length-prefixed framing as demo_rpc.py. The point
 * of this binary existing is that /proc/<pid>/exe points to a native ELF
 * rather than the Python interpreter, so replacing the file on disk and
 * respawning the service changes the binary_hash the kernel sees.
 *
 * This is intentionally terse; it is not production code.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

extern char **environ;

#define MAX_FRAME (16 * 1024 * 1024)

#ifndef BUILD_TAG
#define BUILD_TAG "v1"
#endif
/* Embedded so two builds with different -DBUILD_TAG produce distinct
 * SHA-256 hashes even at the same optimization level. The string is
 * referenced below so the compiler can't discard it. */
static const char kBuildTag[] = "native_echo BUILD_TAG=" BUILD_TAG;

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_reexec = 0;
static const char *g_endpoint = NULL;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

/* SIGUSR1 asks the running process to execve() into the binary at
 * $NATIVE_ECHO_SWAP_TARGET, keeping the same pid. The regression test
 * for the exe-identity cache in mcpd uses this to simulate a backend
 * self-reexec without the supervisor knowing: a PID-only cache would
 * miss the swap; the exe_identity fingerprint (readlink target + stat
 * tuple on /proc/<pid>/exe) catches it. The handler itself only sets
 * a flag — execve is called from the main loop so the signal handler
 * stays trivially async-signal-safe. */
static void on_sigusr1(int sig) {
    (void)sig;
    g_reexec = 1;
}

static int recv_exact(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, (char *)buf + off, n - off, 0);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = send(fd, (const char *)buf + off, n - off, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

static int extract_int(const char *body, const char *key, long long *out) {
    /* tiny, brittle, but enough for the one field we care about */
    char needle[64];
    snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *p = strstr(body, needle);
    if (!p) return -1;
    p = strchr(p + strlen(needle), ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    char *end = NULL;
    long long v = strtoll(p, &end, 10);
    if (end == p) return -1;
    *out = v;
    return 0;
}

static void handle_client(int fd) {
    unsigned char header[4];
    if (recv_exact(fd, header, 4) < 0) return;
    uint32_t length = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16)
                    | ((uint32_t)header[2] << 8) | (uint32_t)header[3];
    if (length == 0 || length > MAX_FRAME) return;

    char *body = (char *)malloc(length + 1);
    if (!body) return;
    if (recv_exact(fd, body, length) < 0) {
        free(body);
        return;
    }
    body[length] = '\0';

    long long req_id = 0;
    (void)extract_int(body, "req_id", &req_id);

    /* Build a fixed-shape response echoing req_id. We don't pretend to
     * parse the payload; that's the point — this is the smallest native
     * backend that still speaks the framing protocol. */
    char resp[512];
    int n = snprintf(
        resp, sizeof resp,
        "{\"req_id\":%lld,\"status\":\"ok\","
        "\"result\":{\"echoed\":true,\"binary\":\"native_echo\"},"
        "\"error\":\"\",\"t_ms\":0}",
        req_id);
    if (n < 0 || n >= (int)sizeof resp) {
        free(body);
        return;
    }

    unsigned char out_hdr[4];
    out_hdr[0] = (unsigned char)((n >> 24) & 0xff);
    out_hdr[1] = (unsigned char)((n >> 16) & 0xff);
    out_hdr[2] = (unsigned char)((n >> 8) & 0xff);
    out_hdr[3] = (unsigned char)(n & 0xff);
    (void)send_all(fd, out_hdr, 4);
    (void)send_all(fd, resp, (size_t)n);
    free(body);
}

static int bind_uds(const char *endpoint) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(endpoint) >= sizeof addr.sun_path) {
        fprintf(stderr, "endpoint too long: %s\n", endpoint);
        close(fd);
        return -1;
    }
    (void)unlink(endpoint);
    strncpy(addr.sun_path, endpoint, sizeof addr.sun_path - 1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 64) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

static void cleanup(void) {
    if (g_endpoint) (void)unlink(g_endpoint);
}

int main(int argc, char **argv) {
    const char *endpoint = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--endpoint") == 0 && i + 1 < argc) {
            endpoint = argv[++i];
        } else if (strncmp(argv[i], "--endpoint=", 11) == 0) {
            endpoint = argv[i] + 11;
        } else if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc) {
            /* accepted for CLI compat with python demos, ignored */
            i++;
        } else if (strncmp(argv[i], "--manifest=", 11) == 0) {
            /* same, ignored */
        }
    }
    if (!endpoint || !endpoint[0]) {
        fprintf(stderr, "usage: %s --endpoint <path>\n", argv[0]);
        return 2;
    }

    g_endpoint = endpoint;
    atexit(cleanup);

    /* Use sigaction, NOT signal(). Linux's signal() sets SA_RESTART by
     * default, which auto-restarts accept() after the handler returns.
     * We want accept() to return EINTR so the main loop can act on
     * g_stop / g_reexec — otherwise SIGUSR1 flips the flag but the
     * process stays blocked in the kernel forever. */
    struct sigaction sa_stop = {0};
    sa_stop.sa_handler = on_signal;
    sigemptyset(&sa_stop.sa_mask);
    sa_stop.sa_flags = 0;
    sigaction(SIGINT, &sa_stop, NULL);
    sigaction(SIGTERM, &sa_stop, NULL);

    struct sigaction sa_usr1 = {0};
    sa_usr1.sa_handler = on_sigusr1;
    sigemptyset(&sa_usr1.sa_mask);
    sa_usr1.sa_flags = 0;
    sigaction(SIGUSR1, &sa_usr1, NULL);

    signal(SIGPIPE, SIG_IGN);

    int srv = bind_uds(endpoint);
    if (srv < 0) return 1;
    printf("[native_echo] serving endpoint=%s %s\n", endpoint, kBuildTag);
    fflush(stdout);

    while (!g_stop) {
        if (g_reexec) {
            const char *swap = getenv("NATIVE_ECHO_SWAP_TARGET");
            if (swap && swap[0]) {
                fprintf(stderr,
                        "[native_echo] SIGUSR1 received, execve -> %s (pid preserved)\n",
                        swap);
                fflush(stderr);
                /* Don't close srv: the swapped binary will bind() again
                 * after unlinking the path, same as a normal restart.
                 * Keeping the fd open is harmless because execve replaces
                 * the address space. */
                char *const argv_next[] = {
                    (char *)swap,
                    "--endpoint", (char *)g_endpoint,
                    NULL,
                };
                execve(swap, argv_next, environ);
                perror("execve");
            }
            g_reexec = 0;
        }
        int cfd = accept(srv, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (g_stop) break;
            perror("accept");
            continue;
        }
        handle_client(cfd);
        close(cfd);
    }

    close(srv);
    return 0;
}
