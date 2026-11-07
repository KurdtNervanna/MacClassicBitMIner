/* hostminer - run the portable mining core on a desktop against a real or
 * fake Stratum server.  Used to prove pool acceptance without the Mac.
 *   hostminer selftest
 *   hostminer <host> <port> <wallet> <worker> [seconds]            */
#include "../minercore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

static int g_fd = -1;

static void tx(void *u, const char *line)
{
    char buf[1024]; int n = snprintf(buf, sizeof buf, "%s\n", line);
    (void)u;
    fprintf(stderr, ">> %s\n", line);
    if (send(g_fd, buf, n, 0) < 0) perror("send");
}

int main(int argc, char **argv)
{
    mc_session s; char acc[MC_MAX_LINE]; int alen = 0; time_t t0, last = 0;
    int secs = 30, rc;
    struct addrinfo hints, *res; char port[16];

    if (argc >= 2 && !strcmp(argv[1], "selftest")) {
        printf("selftest: %s\n", mc_selftest() ? "PASS" : "FAIL");
        return mc_selftest() ? 0 : 1;
    }
    if (argc < 5) { fprintf(stderr, "usage: hostminer <host> <port> <wallet> <worker> [secs]\n"); return 2; }
    if (argc > 5) secs = atoi(argv[5]);
    memset(&hints, 0, sizeof hints); hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    snprintf(port, sizeof port, "%s", argv[2]);
    if ((rc = getaddrinfo(argv[1], port, &hints, &res)) != 0) { fprintf(stderr, "dns: %s\n", gai_strerror(rc)); return 1; }
    g_fd = socket(res->ai_family, res->ai_socktype, 0);
    if (connect(g_fd, res->ai_addr, res->ai_addrlen) < 0) { perror("connect"); return 1; }
    freeaddrinfo(res);
    fcntl(g_fd, F_SETFL, O_NONBLOCK);

    mc_session_init(&s, tx, NULL, argv[3], argv[4], "x");
    mc_start(&s);
    t0 = time(NULL);
    while (time(NULL) - t0 < secs) {
        char tmp[2048]; int n = (int)recv(g_fd, tmp, sizeof tmp, 0);
        if (n == 0) { fprintf(stderr, "server closed\n"); break; }
        if (n > 0) {
            int i;
            for (i = 0; i < n; i++) {
                if (tmp[i] == '\n') {
                    acc[alen] = 0;
                    if (alen) { fprintf(stderr, "<< %.200s%s\n", acc, alen > 200 ? "..." : ""); mc_handle_line(&s, acc); }
                    alen = 0;
                } else if (alen < MC_MAX_LINE - 1) acc[alen++] = tmp[i];
            }
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) { perror("recv"); break; }
        mc_mine(&s, 20000);
        if (time(NULL) != last) {
            last = time(NULL);
            fprintf(stderr, "[%3lds] auth=%d job=%d diff=%u hashes=%u found=%u ok=%u bad=%u %s\n",
                    (long)(last - t0), s.authorized, s.have_job, s.difficulty, s.hashes,
                    s.shares_found, s.shares_ok, s.shares_bad, s.last_error);
        }
        if (!s.have_job || !s.authorized) usleep(5000);
    }
    printf("RESULT hashes=%u found=%u accepted=%u rejected=%u\n",
           s.hashes, s.shares_found, s.shares_ok, s.shares_bad);
    close(g_fd);
    return 0;
}
