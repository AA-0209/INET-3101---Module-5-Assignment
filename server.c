#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_PORT   8080
#define MAX_NAME       255      /* longest filename accepted               */
#define MAX_FILE       255      /* largest file content allowed            */
#define FILES_DIR      "files"  /* the only directory the server serves    */
#define RECV_TIMEOUT_S 5        /* drop clients that go silent             */
#define DRAIN_LIMIT    65536    /* max leftover bytes read before closing  */
#define BACKLOG        8

/* Set to 0 by the signal handler; checked by the accept loop. */
static volatile sig_atomic_t running = 1;

static void on_shutdown_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* Keep calling send() until every byte is out. Returns 0 or -1. */
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

static void send_error(int fd, const char *msg)
{
    char out[128];
    int n = snprintf(out, sizeof out, "ERROR: %s\n", msg);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof out)
        n = (int)sizeof out - 1;
    send_all(fd, out, (size_t)n);
}

/*
 * Read one request line into buf (buf must hold MAX_NAME + 2 bytes).
 * Stops at '\n', at EOF, or when the byte limit is reached.
 *
 * Returns: length of the filename on success
 *          -1 on socket error or timeout
 *          -2 if the client disconnected without sending anything
 *          -3 if the request is longer than MAX_NAME
 */
static ssize_t read_request(int fd, char *buf)
{
    const size_t cap = MAX_NAME + 1;   /* 255 chars + '\n' */
    size_t len = 0;
    int found_newline = 0;

    while (len < cap) {
        ssize_t n = recv(fd, buf + len, cap - len, 0);   /* never past cap */
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;                                       /* client closed */

        char *nl = memchr(buf + len, '\n', (size_t)n);
        len += (size_t)n;
        if (nl) {
            len = (size_t)(nl - buf);
            found_newline = 1;
            break;
        }
    }

    if (!found_newline) {
        if (len == 0)
            return -2;
        if (len >= cap)
            return -3;                                   /* flooding */
    }

    buf[len] = '\0';                                     /* always terminate */
    if (len > 0 && buf[len - 1] == '\r')                 /* allow CRLF */
        buf[--len] = '\0';
    return (ssize_t)len;
}

/* Returns NULL if the filename is safe, otherwise the reason it is not. */
static const char *validate_name(const char *name, size_t len)
{
    if (len == 0)
        return "Empty filename";
    if (strlen(name) != len)                 /* a '\0' hidden inside */
        return "Invalid filename (null byte)";
    if (name[0] == '/')
        return "Absolute paths are not allowed";
    if (strstr(name, ".."))
        return "Path traversal is not allowed";
    if (name[0] == '.')
        return "Hidden files are not allowed";

    for (size_t i = 0; i < len; i++) {       /* whitelist: no '/' at all */
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
            return "Invalid character in filename";
    }
    return NULL;
}

/* Open files/<name>, check its size, and send it. */
static void serve_file(int cfd, const char *name, const char *ip)
{
    char path[sizeof FILES_DIR + 1 + MAX_NAME + 1];
    snprintf(path, sizeof path, "%s/%s", FILES_DIR, name);

    int fd = open(path, O_RDONLY | O_NOFOLLOW);   /* refuse symlinks */
    if (fd < 0) {
        if (errno == ENOENT) {
            printf("[%s] %s: file not found\n", ip, name);
            send_error(cfd, "File not found");
        } else {
            printf("[%s] %s: cannot open (%s)\n", ip, name, strerror(errno));
            send_error(cfd, "Cannot open file");
        }
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        printf("[%s] %s: not a regular file\n", ip, name);
        send_error(cfd, "Not a regular file");
        close(fd);
        return;
    }
    if (st.st_size > MAX_FILE) {
        printf("[%s] %s: too large (%lld bytes)\n", ip, name,
               (long long)st.st_size);
        send_error(cfd, "File exceeds 255 characters");
        close(fd);
        return;
    }

    /* Read at most MAX_FILE + 1 bytes in case the file grew after fstat. */
    char data[MAX_FILE + 1];
    size_t total = 0;
    ssize_t n = 0;
    while (total < sizeof data &&
           (n = read(fd, data + total, sizeof data - total)) > 0)
        total += (size_t)n;
    close(fd);

    if (n < 0) {
        send_error(cfd, "Error reading file");
        return;
    }
    if (total > MAX_FILE) {
        send_error(cfd, "File exceeds 255 characters");
        return;
    }

    printf("[%s] %s: sent %zu bytes\n", ip, name, total);
    send_all(cfd, data, total);
}

static void handle_client(int cfd, const struct sockaddr_in *addr)
{
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof ip);

    /* A client that connects and says nothing gets dropped after a timeout. */
    struct timeval tv = { RECV_TIMEOUT_S, 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    char name[MAX_NAME + 2];
    ssize_t len = read_request(cfd, name);

    if (len == -2) {
        printf("[%s] disconnected before sending a request\n", ip);
        return;
    }
    if (len == -1) {
        printf("[%s] receive error or timeout\n", ip);
        return;
    }
    if (len == -3) {
        printf("[%s] rejected: request longer than %d bytes\n", ip, MAX_NAME);
        send_error(cfd, "Filename too long (max 255)");
        return;
    }

    const char *reason = validate_name(name, (size_t)len);
    if (reason) {
        printf("[%s] rejected: %s\n", ip, reason);
        send_error(cfd, reason);
        return;
    }

    serve_file(cfd, name, ip);
}

/*
 * Close a client cleanly. Reading leftover bytes first (up to a limit)
 * lets the client receive our error message instead of a connection reset.
 */
static void close_client(int cfd)
{
    shutdown(cfd, SHUT_WR);

    struct timeval tv = { 1, 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    char junk[1024];
    size_t drained = 0;
    ssize_t r;
    while (drained < DRAIN_LIMIT &&
           (r = recv(cfd, junk, sizeof junk, 0)) > 0)
        drained += (size_t)r;

    close(cfd);
}

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    if (argc > 1) {
        char *end;
        long p = strtol(argv[1], &end, 10);
        if (*end != '\0' || p < 1 || p > 65535) {
            fprintf(stderr, "Usage: %s [port]\n", argv[0]);
            return 1;
        }
        port = (int)p;
    }

    /* SIGINT/SIGTERM: stop the loop. No SA_RESTART, so accept() wakes up. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_shutdown_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* A client hanging up mid-send must not kill the server. */
    struct sigaction ign;
    memset(&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGPIPE, &ign, NULL);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }

    int yes = 1;   /* lets the port be reused right after a restart */
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);

    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        close(lfd);
        return 1;
    }
    if (listen(lfd, BACKLOG) < 0) {
        perror("listen");
        close(lfd);
        return 1;
    }

    printf("Server listening on port %d, serving ./%s/ (Ctrl+C to stop)\n",
           port, FILES_DIR);
    fflush(stdout);

    while (running) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof cli;
        int cfd = accept(lfd, (struct sockaddr *)&cli, &clen);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;          /* signal arrived; loop re-checks running */
            perror("accept");
            continue;
        }
        handle_client(cfd, &cli);
        close_client(cfd);
        fflush(stdout);
    }

    close(lfd);
    printf("\nShutdown signal received. Listening socket closed, port %d released.\n",
           port);
    return 0;
}