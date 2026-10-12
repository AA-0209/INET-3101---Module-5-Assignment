#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8080
#define MAX_NAME     255

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

int main(int argc, char *argv[])
{
    const char *host = argc > 1 ? argv[1] : DEFAULT_HOST;
    int port = DEFAULT_PORT;
    if (argc > 2) {
        char *end;
        long p = strtol(argv[2], &end, 10);
        if (*end != '\0' || p < 1 || p > 65535) {
            fprintf(stderr, "Usage: %s [host] [port]\n", argv[0]);
            return 1;
        }
        port = (int)p;
    }

    /* Room for 255 chars + '\n' + '\0'. */
    char name[MAX_NAME + 2];
    printf("Enter filename: ");
    fflush(stdout);
    if (!fgets(name, sizeof name, stdin)) {
        fprintf(stderr, "No input.\n");
        return 1;
    }

    size_t len = strcspn(name, "\n");
    if ((name[len] != '\n' && !feof(stdin)) || len > MAX_NAME) {
        fprintf(stderr, "Filename too long (max %d characters).\n", MAX_NAME);
        return 1;
    }
    if (len == 0) {
        fprintf(stderr, "Filename cannot be empty.\n");
        return 1;
    }
    name[len] = '\n';          /* the newline marks the end of the request */

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", host);
        close(fd);
        return 1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    if (send_all(fd, name, len + 1) < 0) {
        perror("send");
        close(fd);
        return 1;
    }

    /* Print everything the server sends until it closes the connection. */
    char buf[512];
    size_t total = 0;
    char last = '\n';
    ssize_t n;
    while ((n = recv(fd, buf, sizeof buf, 0)) > 0) {
        fwrite(buf, 1, (size_t)n, stdout);
        total += (size_t)n;
        last = buf[n - 1];
    }
    if (n < 0)
        perror("recv");
    if (total == 0)
        printf("(no response from server)\n");
    else if (last != '\n')
        printf("\n");

    close(fd);
    return 0;
}