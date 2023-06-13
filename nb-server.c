/* According to earlier standards */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include <unistd.h>
#include <fcntl.h>

#ifndef __USE_MISC
    #define __USE_MISC
#endif

#include <net/if_arp.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include "nb.h"


struct nb_peer_t {
    struct nb_peer_t *next;
    struct context_t ctx;
    int die;
    int fd;
    u_int8_t mac[6];
    char group[32];

    u_int16_t need_bytes;
    u_int16_t pdu_len;
    u_int8_t pdu[2048];
};

int nb_peer_create(int fd, struct nb_peer_t **pc)
{
    struct nb_peer_t *c;

    c = (struct nb_peer_t *)malloc(sizeof(struct nb_peer_t));
    if (!c) {
        nb_log_error("could not alloc peer object, errno: %d\n", errno);
        return -1;
    }
    memset(c, 0, sizeof(*c));
    c->fd = fd;

    *pc = c;
    return 0;
}


struct nb_server_t {
    int fd;

    int peers_nr;
    struct nb_peer_t *peers;
};
const u_int8_t mac_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int nb_authrize_check(const char *username, const char *password)
{
    return 0;
}

int nb_peer_readable(const struct nb_server_t *s, struct nb_peer_t *c)
{
    int result = 0;

    co_begin(c->ctx);
    c->pdu_len = 0;
    c->need_bytes = 0;
    while (c->pdu_len < 2) {
        result = recv(c->fd, &c->pdu[c->pdu_len], 2, 0);
        if (result <= 0) {
            c->die ++;
            nb_log_info("%s:%d connection [%d] closed by remote or GWF.\n", __FILE__, __LINE__, c->fd);
            return -1;
        }
        c->pdu_len += result;

        if (c->pdu_len == 2) {
            break;            
        }
        co_yield(c->ctx, 0);
    }

    c->need_bytes = c->pdu[0] + c->pdu[1] * 256 + 2;
    // we shold return here and wait next readable event comes.
    co_yield(c->ctx, 0);

    while (c->pdu_len < c->need_bytes) {
        int remain_bytes = c->need_bytes - c->pdu_len;
        nb_log_trace("total: %d, pdu: %d, remain: %d\n", c->need_bytes, c->pdu_len, remain_bytes);
        assert(c->pdu_len + remain_bytes < sizeof(c->pdu));
        result = recv(c->fd, &c->pdu[c->pdu_len], remain_bytes, 0);
        if (result <= 0) {
            c->die ++;
            nb_log_info("%s:%d connection [%d] closed by remote or GWF.\n", __FILE__, __LINE__, c->fd);
            return -1;
        }
        c->pdu_len += result;
        if (c->pdu_len == c->need_bytes) {
            break;
        }
        co_yield(c->ctx, 0);
    }

    nb_dump_buff("net rx", c->pdu, c->pdu_len);
    switch (c->pdu[2])
    {
    case 0 ... 63: // login
    {
        struct nb_login_t *login = (struct nb_login_t *)(void *)(&c->pdu[3]);
        result = nb_authrize_check(login->username, login->password);
        if (result != 0) {
            c->die ++;
            nb_log_info("%s:%d [%d] authurize fail.\n", __FILE__, __LINE__, c->fd);
            return -1;
        }

        result = net_send_login_ack(c->fd, 0, -1);
        if (result != 0) {
            c->die ++;
            nb_log_info("%s:%d [%d] could not send a replay.\n", __FILE__, __LINE__, c->fd);
            return -1;
        }

        memcpy(c->mac, login->mac, sizeof(mac_broadcast));
        memcpy(c->group, login->group, sizeof(login->group));
        co_reset(c->ctx);
    }
    break;

    case 64 ... 127: // login ack
    {
        c->die ++;
        nb_log_info("%s:%d [%d] invalid login ack package.\n", __FILE__, __LINE__, c->fd);
        return -1;
    }
    break;

    case 128 ... 191: // pack
    {
        int tun_bytes = c->need_bytes;
        struct nb_peer_t *peer;
        u_int8_t *mac_dst = &(c->pdu[3]), *mac_src = &(c->pdu[9]);

        if (0 == strlen(c->group)) {
            c->die ++;
            nb_log_warn("%s:%d [%d] invalid package, peer not login, pack dropped\n", __FILE__, __LINE__, c->fd);
            return 0;
        }

        for (peer = s->peers; peer; peer = peer->next) {
            if (peer->fd == c->fd) continue; // myself

            if (0 == strlen(peer->group)) continue; // peer not join any group yet.

            if (0 != strncmp(peer->group, c->group, sizeof(c->group))) continue; // group name is diffrent from `c`

            if (0 != memcmp(mac_dst, mac_broadcast, sizeof(mac_broadcast)) 
                && 0 != memcmp(mac_dst, peer->mac, sizeof(mac_broadcast))) continue; // mac not match
            
            (void)send(peer->fd, c->pdu, c->pdu_len, 0);
        }
        co_reset(c->ctx);
    }
    break;

    case 192 ... 255: // mass
        // every thing is ok.
        co_reset(c->ctx);
    break;
    }

    co_end(c->ctx);

    return 0;
}

void show_help(int argc, char * const *argv)
{
    printf("Welcome to %s\n", argv[0]);
    printf("Built on %s %s\n", __DATE__, __TIME__);
    printf("Copyright 2023-06 - https://www.ggabc.vip/nb\n");
    printf("  -b|--bind [string]: which ip to listen, use all ip if not gaven.\n");
    printf("  -p|--port [int]: server listen port, default: 9999\n");
    printf("  -x|--vv: show communication data stream as hex.\n");
    printf("  -h|--help: show this message.\n");
    printf("Report bugs <bug@ggabc.vip>\n");
}

int nb_server_create(int argc, char * const *argv, struct nb_server_t **ps)
{
    struct nb_server_t *s = NULL;
    int fd, error;
    uint32_t value;
    struct sockaddr_in addr;
    const char *bind_ip = NULL;
    uint16_t port = 9999;

    *ps = NULL;
    static struct option long_options[] = {
        {"bind",       required_argument, 0,  'b'},
        {"port",       required_argument, 0,  'p'},
        {"vv",         required_argument, 0,  'x'},
        {"help",       no_argument,       0,  'h'},
        {0,         0,                 0,  0 }
    };
    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0, ch;
        ch = getopt_long(argc, argv, "b:p:xh", long_options, &option_index);
        if (ch == -1) {
            break;
        }
        switch (ch)
        {
        case 'b':
            bind_ip = optarg;
        break;
        case 'p':
            port = atoi(optarg);
        break;
        case 'x':
            nb_buff_dump_toggle();
        break;
        case 'h':
            show_help(argc, argv);
        return 0;
        }
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        nb_log_fault("could not start a server.\n");
        return -1;
    }

    value = 1;
    error = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value));
    if (error) {
        nb_log_fault("could setup a socket option SO_REUSEPORT.\n");
        close(fd);
        return -1;
    }

    struct in_addr listen_addr = {.s_addr = INADDR_ANY};
    if (bind_ip) {
        inet_aton(bind_ip, &listen_addr);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = listen_addr.s_addr;
    error = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (error) {
        nb_log_fault("could bind on port %d.\n", port);
        close(fd);
        return -1;
    }

    error = listen(fd, 10);
    if (error) {
        nb_log_fault("listen port %d fail.\n", port);
        close(fd);
        return -1;
    }

    s = (struct nb_server_t *)malloc(sizeof(*s));
    if (!s) {
        close(fd);
        return -1;
    }

    memset(s, 0, sizeof(*s));
    s->fd = fd;

    nb_log_info("nb server on: %s:%d.\n", inet_ntoa(listen_addr), port);

    *ps = s;
    return 0;
}

int nb_server_poll(struct nb_server_t *s)
{
    int result = -1, fd_nr;
    fd_set for_read;
    struct timeval tv;
    struct nb_peer_t *peer;

    int peer_closed_nr = 0;
    struct nb_peer_t *peer_closed[100];

    if (!s) {
        return 0;
    }

    while (1)
    {
        fd_nr = 0;
        FD_ZERO(&for_read);

        if (s->peers_nr < 100) {
            fd_nr = s->fd > fd_nr ? s->fd : fd_nr;
            FD_SET(s->fd, &for_read);
        }
        for (peer = s->peers; peer; peer = peer->next) {
            fd_nr = peer->fd > fd_nr ? peer->fd : fd_nr;
            FD_SET(peer->fd, &for_read);
        }

        tv.tv_sec = 10;
        tv.tv_usec = 0;

        result = select(fd_nr + 1, &for_read, NULL, NULL, &tv);
        if (0 == result) {
            continue;
        }
        if (result < 0) {
            break;
        }

        if (FD_ISSET(s->fd, &for_read)) {
            struct sockaddr_in addr;
            struct nb_peer_t *new_peer, **it;
            int new_fd;
            socklen_t size = sizeof(addr);
            new_fd = accept(s->fd, (struct sockaddr *)&addr, &size);
            if (new_fd < 0) {
                nb_log_error("accept new connection fail, error no: %d\n", errno);
            }

            result = nb_peer_create(new_fd, &new_peer);
            if (0 != result) {
                close(new_fd);
            } else {
                it =  &(s->peers);
                while (*it) it = &((*it)->next);
                *it = new_peer;
                s->peers_nr ++;
                nb_log_info("new connection establised, peers count: %d\n", s->peers_nr);
            }
        }

        // process peer readable.
        peer_closed_nr = 0;
        for (peer = s->peers; peer; peer = peer->next) {
            if (!FD_ISSET(peer->fd, &for_read)) continue;
            result = nb_peer_readable(s, peer);
            if (result >= 0) continue;
            peer_closed[peer_closed_nr ++] = peer;
        }

        // process closed peer
        for (int i = 0; i < peer_closed_nr; i ++) {
            struct nb_peer_t **it = &(s->peers);
            peer = peer_closed[i];
            while (*it && *it != peer) it = &((*it)->next);
            if (*it) {
                // found now.
                *it = (*it)->next;
            }
            nb_log_trace("connection %d destryed.\n", peer->fd);
            close(peer->fd);
            free(peer);
        }
        s->peers_nr -= peer_closed_nr;
    }

    return result;
}

int nb_server_destroy(struct nb_server_t *s, int code)
{
    struct nb_peer_t **it, *peer;

    if (!s) {
        return code;
    }

    if (s->fd > 0) {
        close(s->fd);
        s->fd = 0;
    }

    it =  &(s->peers);
    while (*it) {
        peer = *it;
        it = &((*it)->next);
        if (peer->fd > 0) {
            close(peer->fd);
            free(peer);
        }
    }

    free(s);
    return code;
}

int main(int argc, char * const *argv)
{
    struct nb_server_t *s = NULL;
    int error;

    error = nb_server_create(argc, argv, &s);
    assert(0 == error);

    error = nb_server_poll(s);
    return nb_server_destroy(s, error);
}