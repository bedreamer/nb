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

struct nb_client_t {
    struct context_t ctx;
    u_int16_t need_bytes;
    u_int16_t pdu_len;
    u_int8_t pdu[2048];

    int net_fd;
    int tun_fd;

    const char *server_ip;
    uint16_t server_port;
    const char *group, *username, *password;
    uint8_t mac[6];
};
static const char *default_iface_name = "nb0";
static const char *default_server_ip = "127.0.0.1";
static const char *default_group_name = "test";
static const uint16_t default_server_port = 9999;
//   2  5  8  B  E
// 01:34:67:9A:CD:Ex
void strtomac(const char *mac_str, uint8_t *mac)
{
    char buff[20] =  {0};
    strncpy(buff, mac_str, sizeof(buff));

    for (int i = 0, j = 0; j < 6; i += 3, j ++)
    {
        buff[i + 2] = 0;
        mac[j] = strtol(buff + i, NULL, 16);
    }
}

int nb_tun_open(const char *iface_name, uint8_t *mac, int mac_valid, const char *ip, const char *netmask, int mtu)
{
    char *tuntap_device = "/dev/net/tun";
    char dev[IFNAMSIZ] = "nb0";
    int tun_fd;
    struct ifreq ifr;
    int rc;

    if (iface_name) {
        strncpy(dev, iface_name, sizeof(dev));
    }

    tun_fd = open(tuntap_device, O_RDWR);
    if(tun_fd < 0) {
        nb_log_error("tuntap open() error: %s[%d]. Is the tun kernel module loaded?\n", strerror(errno), errno);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    // want a TAP device for layer 2 frames
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';
    rc = ioctl(tun_fd, TUNSETIFF, (void *)&ifr);

    // sync mac
    if (mac_valid) {
        ioctl(tun_fd, SIOCGIFHWADDR, (void *)&ifr);
        memcpy(ifr.ifr_hwaddr.sa_data, mac, IFHWADDRLEN);
        rc = ioctl(tun_fd, SIOCSIFHWADDR, (void *)&ifr);
        nb_log_info("set mac address, code: %d, errno: %d (%s)\n", rc, errno, strerror(errno));
    } else {
        ioctl(tun_fd, SIOCGIFHWADDR, (void *)&ifr);
        memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    memset(&ifr, 0, sizeof(ifr));

    // setup ip
    struct sockaddr_in *addr = (struct sockaddr_in *)(&ifr.ifr_addr);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    inet_aton(ip, &addr->sin_addr);
    nb_dump_buff("ip:", ifr.ifr_addr.sa_data, sizeof(ifr.ifr_addr.sa_data));
    rc = ioctl(fd, SIOCSIFADDR, (void *)&ifr);
    nb_log_info("set ip address, code: %d, errno: %d (%s)\n", rc, errno, strerror(errno));

    // bring up interface
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFFLAGS, (void *)&ifr);
    ifr.ifr_flags |= IFF_UP|IFF_RUNNING;
    rc = ioctl(fd, SIOCSIFFLAGS, (void *)&ifr);
    nb_log_info("bring up interface, code: %d, errno: %d (%s)\n", rc, errno, strerror(errno));

    // setup netmask
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    inet_aton(netmask, &addr->sin_addr);
    rc = ioctl(fd, SIOCSIFNETMASK, (void *)&ifr);
    nb_log_info("setup netmask, code: %d, errno: %d (%s)\n", rc, errno, strerror(errno));

    close(fd);

    if(rc < 0) {
        nb_log_error("tuntap ioctl(TUNSETIFF, IFF_TAP) error: %s[%d]\n", strerror(errno), rc);
        close(tun_fd);
        return -1;
    }

    return tun_fd;
}

void show_help(int argc, char * const *argv)
{
    printf("Welcome to %s\n", argv[0]);
    printf("Built on %s %s\n", __DATE__, __TIME__);
    printf("Copyright 2023-06 - https://www.ggabc.vip/nb\n");
    printf("  -s|--server [string]: server ip address, *required*\n");
    printf("  -p|--port [int]: server port, default: 9999\n");
    printf("  -i|--iface [string]: network card name, default: nb0\n");
    printf("  -g|--group [string]: communication group name, default: test\n");
    printf("  -u|--username [string]: login username, default: test\n");
    printf("  -P|--password [string]: login password, default: test\n");
    printf("  -m|--mac [string]: iface hw address.\n");
    printf("  -I|--ip [string]: network ip address, *required*\n");
    printf("  -N|--netmask [string]: network mask, default: 255.255.255.0\n");
    printf("  -T|--mtu [int]: MTU, default: 1500\n");
    printf("  -x|--vv: show communication data stream as hex.\n");
    printf("  -h|--help: show this message.\n");
    printf("Report bugs <bug@ggabc.vip>\n");
}


int nb_client_create(int argc, char *const *argv, struct nb_client_t **cc)
{
    struct nb_client_t *c;
    int tun_fd;
    const char *iface_name = default_iface_name, *server_ip = NULL;
    const char *group_name = default_group_name;
    const char *username = "test", *password = "test";
    const char *ip = NULL, *netmask = "255.255.255.0";
    int mtu = 1500;
    uint8_t user_define_mac[6] = {0};
    int is_user_define_mac = 0;
    uint16_t server_port = default_server_port;

    *cc = NULL;

    static struct option long_options[] = {
        {"server",    required_argument, 0,   's'},
        {"port",       required_argument, 0,  'p'},
        {"iface",      required_argument, 0,  'i'},
        {"group",      required_argument, 0,  'g'},
        {"username",   required_argument, 0,  'u'},
        {"password",   required_argument, 0,  'P'},
        {"mac",        required_argument, 0,  'm'},
        {"ip",         required_argument, 0,  'I'},
        {"netmask",    required_argument, 0,  'N'},
        {"mtu",        required_argument, 0,  'U'},
        {"vv",         required_argument, 0,  'x'},
        {"help",       no_argument,       0,  'h'},
        {0,         0,                 0,  0 }
    };
    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0, ch;
        ch = getopt_long(argc, argv, "s:p:i:g:u:P:m:I:N:U:xh", long_options, &option_index);
        if (ch == -1) {
            break;
        }
        switch (ch)
        {
        case 's':
            server_ip = optarg;
        break;
        case 'p':
            server_port = atoi(optarg);
        break;
        case 'i':
            iface_name = optarg;
        break;
        case 'g':
            group_name = optarg;
        break;
        case 'u':
            username = optarg;
        break;
        case 'P':
            password = optarg;
        break;
        case 'm':
            is_user_define_mac = 1;
            strtomac(optarg, user_define_mac);
        break;
        case 'I':
            ip = optarg;
        break;
        case 'N':
            netmask = optarg;
        break;
        case 'U':
            mtu = atoi(optarg);
            mtu = mtu < 1000 ? 1000 : mtu;
        break;
        case 'x':
            nb_buff_dump_toggle();
        break;
        case 'h':
            show_help(argc, argv);
        return 0;
        }
    }

    if (!ip || !username || !password || !server_ip) {
        show_help(argc, argv);
        return 0;
    }

    nb_log_trace("server: %s:%d\n", server_ip, server_port);
    nb_log_trace("iface: %s\n", iface_name);
    nb_log_trace("group: %s\n", group_name);
    nb_log_trace("username: %s\n", username);
    nb_log_trace("password: %s\n", password);
    nb_log_trace("ip: %s\n", ip);
    nb_log_trace("netmask: %s\n", netmask);
    nb_log_trace("mtu: %d\n", mtu);

    tun_fd = nb_tun_open(iface_name, user_define_mac, is_user_define_mac, ip, netmask, mtu);
    if (tun_fd < 0) {
        return -1;
    }
    nb_log_trace("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        user_define_mac[0], user_define_mac[1], user_define_mac[2], user_define_mac[3], user_define_mac[4], user_define_mac[5]);

    c = (struct nb_client_t *)malloc(sizeof(*c));
    if (!c) {
        close(tun_fd);
        return -1;
    }

    c->server_ip = server_ip;
    c->server_port = server_port;
    c->group = group_name;
    c->username = username;
    c->password = password;
    memcpy(c->mac, user_define_mac, sizeof(c->mac));
    c->net_fd = -1;
    c->tun_fd = tun_fd;
    *cc = c;

    return 0;
}

int nb_client_make_connection(struct nb_client_t *c)
{
    int net_fd;
    int rc;
    struct sockaddr_in addr;
    struct nb_login_t pdu;
    uint8_t mac[6];

    net_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (net_fd < 0) {
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(c->server_port);    
    inet_aton(c->server_ip, &addr.sin_addr);

    rc = connect(net_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        close(net_fd);
        return -1;
    }
    nb_log_info("connection to %s:%d establised.\n", c->server_ip, c->server_port);

    rc = nb_net_send_mass(net_fd, rand() % 800);

    memset(&pdu, 0, sizeof(pdu));
    memcpy(pdu.mac, c->mac, sizeof(mac));
    memcpy(pdu.group, c->group, sizeof(pdu.group) - 1);
    memcpy(pdu.password, c->password, sizeof(pdu.password) - 1);
    memcpy(pdu.username, c->username, sizeof(pdu.username) - 1);
    rc = nb_net_send_login(net_fd, &pdu, -1);
    if (rc) {
        close(net_fd);
        return -1;
    }

    c->net_fd = net_fd;
    return 0;
}

int nb_client_net_readable(struct nb_client_t *c)
{
    int result = 0;

    co_begin(c->ctx);
    c->pdu_len = 0;
    c->need_bytes = 0;
    while (c->pdu_len < 2) {
        result = recv(c->net_fd, &c->pdu[c->pdu_len], 2, 0);
        if (result <= 0) {
            nb_log_info("%s:%d connection [%d] closed by remote or GWF.\n", __FILE__, __LINE__, c->net_fd);
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
        result = recv(c->net_fd, &c->pdu[c->pdu_len], remain_bytes, 0);
        if (result <= 0) {
            nb_log_info("%s:%d connection [%d] closed by remote or GWF.\n", __FILE__, __LINE__, c->net_fd);
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
        nb_log_info("%s:%d connection [%d] closed by remote or GWF.\n", __FILE__, __LINE__, c->net_fd);
        return -1;
    }
    break;

    case 64 ... 127: // login ack
    {
        co_reset(c->ctx);
    }
    break;

    case 128 ... 191: // pack
    {
        int tun_bytes = c->need_bytes;
        struct nb_peer_t *peer;
        u_int8_t *mac_dst = &(c->pdu[3]), *mac_src = &(c->pdu[9]);
        write(c->tun_fd, &c->pdu[3], c->pdu_len - 3);
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

int nb_client_tun_readable(struct nb_client_t *c)
{
    uint8_t buff[CONFIG_NB_MAX_PACK];
    int len;

    len = read(c->tun_fd, buff, sizeof(buff));
    if (len > 0) {
        nb_dump_buff("tun readable\n", buff, len);
    }

    nb_net_send_pack(c->net_fd, buff, len);

    return 0;
}

int nb_client_poll(struct nb_client_t *c)
{
    int rc;
    fd_set for_read;
    struct timeval tv;

    if (!c) {
        return 0;
    }

    while (1)
    {
        FD_ZERO(&for_read);

        tv.tv_sec = 10;
        tv.tv_usec = 0;

        while (c->net_fd <= 0) {
            nb_client_make_connection(c);
        }

        FD_SET(c->net_fd, &for_read);
        int nrfd = c->net_fd > c->tun_fd ? c->net_fd + 1 : c->tun_fd + 1;
        FD_SET(c->tun_fd, &for_read);

        rc = select(nrfd, &for_read, NULL, NULL, &tv);
        if (0 == rc) {
            continue;
        }
        if (c->net_fd > 0 && FD_ISSET(c->net_fd, &for_read)) {
            rc = nb_client_net_readable(c);
            if (rc < 0) {
                close(c->net_fd);
                c->net_fd = -1;
                nb_log_warn("connection closed.\n");
            }
        }

        if (FD_ISSET(c->tun_fd, &for_read)) {
            rc = nb_client_tun_readable(c);
        }
    }
}

int nb_client_destroy(struct nb_client_t *c, int error)
{
    return error;
}

int main(int argc, char *const *argv)
{
    struct nb_client_t *client;
    int error;

    error = nb_client_create(argc, argv, &client);
    assert(0 == error);

    error = nb_client_poll(client);

    return nb_client_destroy(client, error);
}