#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include "nb.h"

static int enable_nb_buff_dump = 0;

int nb_buff_dump_toggle()
{
    enable_nb_buff_dump = enable_nb_buff_dump ? 0 : 1;
    return enable_nb_buff_dump;
}

int nb_net_recv_frame(int fd, uint8_t *buff)
{
    int size, need;
    uint8_t head[2];

    size = read(fd, head, 2);
    if (size != 2) {
        return -1;
    }

    need = head[0] + head[1] << 8;
    size = read(fd, buff, need);
    if (size != need) {
        return -1;
    }

    return size;
}

int nb_net_send_frame(int fd, uint8_t *buff, int size)
{
    uint8_t mtu[CONFIG_NB_MTU_MAX];
    int len;

    mtu[0]  = size & 0xff;
    mtu[1]  = size / 256;
    memcpy(&mtu[2], buff, size);

    nb_dump_buff("net tx", mtu, size + 2);

    len = send(fd, mtu, size + 2, 0);
    if (len == size + 2) {
        return size;
    }

    return -1;
}

int nb_net_send_pack(int fd, uint8_t *buff, int size)
{
    uint8_t mtu[CONFIG_NB_MTU_MAX];
    int len;

    mtu[0] = (rand() % 64 + 128) & 0xff;
    memcpy(&mtu[1], buff, size);
    len = nb_net_send_frame(fd, mtu, size + 1);

    if (len == size + 1) {
        return size;
    }

    return -1;
}

int nb_net_send_mass(int fd, int mass_size)
{
    uint8_t buff[CONFIG_NB_MTU_MAX];
    int len, result;
    if (mass_size < 10) {
        mass_size = rand() % 100 + 10;
    }

    len = 0;
    buff[len ++] = (rand() % 64 + 192) & 0xff;
    while (mass_size -- > 0) {
        buff[len ++] = rand() % 256;
    }

    result = nb_net_send_frame(fd, buff, len);
    if (result == len) {
        return 0;
    }

    return -1;
}

int nb_net_send_login(int fd, struct nb_login_t *login, int mass_size)
{
    uint8_t buff[200];
    int len, result;

    len = 0;
    buff[len ++] = (rand() % 64 + 0) & 0xff;
    memcpy(&buff[len], login, sizeof(*login));
    len += sizeof(*login);

    if (mass_size < 10) {
        mass_size = rand() % 10 + 10;
    }
    while (mass_size -- > 0) {
        buff[len ++] = rand() % 256;
    }

    result = nb_net_send_frame(fd, buff, len);
    if (result == len) {
        return 0;
    }

    return -1;
}

int net_send_login_ack(int fd, int result, int mass_size)
{
    uint8_t buff[200];
    int len;

    len = 0;
    buff[len ++] = (rand() % 64 + 64) & 0xff;
    buff[len ++] = result & 0xff;
    if (mass_size < 10) {
        mass_size = rand() % 10 + 10;
    }
    while (mass_size -- > 0) {
        buff[len ++] = rand() % 256;
    }

    result = nb_net_send_frame(fd, buff, len);
    if (result == len) {
        return 0;
    }

    return -1;
}


void nb_dump_buff(const char *title, uint8_t *buff, int size)
{
    if (!enable_nb_buff_dump) return;

    if (title) {
        printf("%s [%d]", title, size);
    }

    for (int i = 0; i < size; i ++) {
        printf("%02x ", buff[i]);
    }
    printf("\n");
}
