#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT_S    3
#define REPLY_CAP    8192

static const char *g_host = "127.0.0.1";
static int         g_port = 8080;

static const char GOOD_FILE[] = "hello.txt\n";

static int g_passed = 0;
static int g_total  = 0;

/* Open a TCP connection to the server. Returns fd or -1. */
static int connect_server(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct timeval tv = { TIMEOUT_S, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((unsigned short)g_port);
    if (inet_pton(AF_INET, g_host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Keep sending until every byte is out. Returns 0, or -1 on error. */
static int send_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, buf, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

/*
 * Send a raw payload, half-close the write side, and read the whole reply.
 * The reply is copied into out (NUL-terminated); returns its length, or
 * -1 if the connection could not be opened.
 */
static ssize_t send_payload(const char *payload, size_t plen,
                            char *out, size_t outcap)
{
    int fd = connect_server();
    if (fd < 0)
        return -1;

    send_all(fd, payload, plen);      /* ignore send errors: peer may reset */
    shutdown(fd, SHUT_WR);

    size_t total = 0;
    ssize_t n;
    while (total < outcap - 1 &&
           (n = recv(fd, out + total, outcap - 1 - total, 0)) > 0)
        total += (size_t)n;

    close(fd);
    out[total] = '\0';
    return (ssize_t)total;
}

/* A normal request must still succeed after each attack. */
static int server_alive(void)
{
    char reply[REPLY_CAP];
    ssize_t n = send_payload(GOOD_FILE, strlen(GOOD_FILE), reply, sizeof reply);
    if (n <= 0)
        return 0;
    return strncmp(reply, "ERROR", 5) != 0;
}

/* Trim the reply to one line for tidy printing. */
static void first_line(const char *s, char *dst, size_t cap)
{
    size_t i = 0;
    while (i < cap - 1 && s[i] && s[i] != '\n') {
        dst[i] = s[i];
        i++;
    }
    dst[i] = '\0';
}

/*
 * Run one attack and score it.
 *   expect_error != 0  -> the server must reply with an "ERROR:" line.
 * The server must always stay alive and must never leak /etc/passwd.
 */
static void attack(const char *category, const char *name,
                   const char *payload, size_t plen, int expect_error)
{
    char reply[REPLY_CAP];
    ssize_t n = send_payload(payload, plen, reply, sizeof reply);

    int leaked    = (n > 0) && (strstr(reply, "root:") != NULL);
    int got_error = (n > 0) && (strncmp(reply, "ERROR", 5) == 0);
    int alive     = server_alive();

    int ok = alive && !leaked;
    if (expect_error)
        ok = ok && got_error;

    g_total++;
    if (ok)
        g_passed++;

    char snippet[64];
    first_line(reply, snippet, sizeof snippet);
    printf("[%s] %-11s %-38s reply=\"%s\"\n",
           ok ? "PASS" : "FAIL", category, name, snippet);
    if (leaked)
        printf("       !!! /etc/passwd contents leaked\n");
    if (!alive)
        printf("       !!! server stopped responding\n");
}

/* A teardown case: run a disconnect action, then just check the server lives. */
static void teardown(const char *name, void (*action)(void))
{
    action();
    struct timespec ts = { 0, 200 * 1000 * 1000 };   /* 200 ms */
    nanosleep(&ts, NULL);

    int alive = server_alive();
    g_total++;
    if (alive)
        g_passed++;
    printf("[%s] %-11s %-38s reply=\"\"\n",
           alive ? "PASS" : "FAIL", "Teardown", name);
    if (!alive)
        printf("       !!! server stopped responding\n");
}

/* Close a socket with a TCP RST instead of a normal FIN. */
static void reset_close(int fd)
{
    struct linger lg = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(fd);
}

/* ---------- teardown actions ---------- */

static void connect_and_close(void)
{
    int fd = connect_server();
    if (fd >= 0)
        close(fd);
}

static void partial_then_close(void)
{
    int fd = connect_server();
    if (fd < 0)
        return;
    send_all(fd, "hel", 3);
    close(fd);
}

static void partial_then_reset(void)
{
    int fd = connect_server();
    if (fd < 0)
        return;
    send_all(fd, "hello", 5);
    reset_close(fd);
}

static void leave_before_reply(void)
{
    int fd = connect_server();
    if (fd < 0)
        return;
    send_all(fd, GOOD_FILE, strlen(GOOD_FILE));
    reset_close(fd);
}

static void idle_then_close(void)
{
    int fd = connect_server();
    if (fd < 0)
        return;
    sleep(1);
    close(fd);
}

static void burst_of_connections(void)
{
    for (int i = 0; i < 50; i++)
        connect_and_close();
}

int main(int argc, char *argv[])
{
    if (argc > 1)
        g_host = argv[1];
    if (argc > 2) {
        g_port = atoi(argv[2]);
        if (g_port < 1 || g_port > 65535) {
            fprintf(stderr, "Usage: %s [host] [port]\n", argv[0]);
            return 1;
        }
    }

    /* A peer reset while we send must not kill the fuzzer. */
    signal(SIGPIPE, SIG_IGN);

    printf("Fuzzing %s:%d\n\n", g_host, g_port);

    if (!server_alive()) {
        printf("Server not reachable or files/hello.txt missing. "
               "Start ./server first.\n");
        return 2;
    }

    /* Baseline and required error cases */
    attack("Baseline", "valid file",                  GOOD_FILE, strlen(GOOD_FILE), 0);
    attack("Baseline", "missing file",                "nope.txt\n", 9, 1);
    attack("Baseline", "oversized file (>255 bytes)", "big.txt\n", 8, 1);

    /* 1. Path traversal */
    attack("Traversal", "../../etc/passwd",          "../../etc/passwd\n", 17, 1);
    attack("Traversal", "absolute /etc/passwd",      "/etc/passwd\n", 12, 1);
    attack("Traversal", "../server.c",               "../server.c\n", 12, 1);
    attack("Traversal", "files/../../etc/passwd",    "files/../../etc/passwd\n", 23, 1);
    attack("Traversal", "....//....//etc/passwd",    "....//....//etc/passwd\n", 23, 1);
    attack("Traversal", "backslash ..\\..\\",        "..\\..\\etc\\passwd\n", 16, 1);
    attack("Traversal", "URL-encoded %2e%2e%2f",     "%2e%2e%2f%2e%2e%2fetc%2fpasswd\n", 30, 1);

    /* 2. Buffer overflow / flooding */
    {
        static char big[1000001];

        memset(big, 'A', 10000);
        attack("Flood", "10,000 bytes, no newline", big, 10000, 1);

        memset(big, 'A', 256);
        big[256] = '\n';
        attack("Flood", "256 bytes + newline", big, 257, 1);

        memset(big, 'A', 255);
        big[255] = '\n';
        attack("Flood", "255 bytes + newline (limit)", big, 256, 1);

        memset(big, 'A', 1000000);
        attack("Flood", "1,000,000 bytes", big, 1000000, 1);

        /* binary garbage: 0..255 repeated */
        char garbage[256 * 40];
        for (size_t i = 0; i < sizeof garbage; i++)
            garbage[i] = (char)(i % 256);
        attack("Flood", "binary garbage", garbage, sizeof garbage, 0);
    }

    /* 3. Abrupt disconnects */
    teardown("connect then close immediately", connect_and_close);
    teardown("half a filename then close",      partial_then_close);
    teardown("half a filename then TCP reset",  partial_then_reset);
    teardown("request then reset before reply", leave_before_reply);
    teardown("idle connection then close",      idle_then_close);
    teardown("50 rapid connect/close",          burst_of_connections);

    /* 4. Null byte injection (lengths include the embedded '\0') */
    {
        const char p1[] = "hello.txt\x00../../etc/passwd\n";
        attack("NullByte", "hello.txt\\0../../etc/passwd", p1, sizeof p1 - 1, 1);

        const char p2[] = "\x00\n";
        attack("NullByte", "\\0 only", p2, sizeof p2 - 1, 1);

        const char p3[] = "hello\x00.txt\n";
        attack("NullByte", "hello\\0.txt", p3, sizeof p3 - 1, 1);

        const char p4[] = "../\x00/etc/passwd\n";
        attack("NullByte", "../\\0/etc/passwd", p4, sizeof p4 - 1, 1);
    }

    printf("\n%d/%d tests passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}