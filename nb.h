/**
 * @brief 这是一个自动创建的头文件
 * @date 20230612153121UTC
 */
#ifndef _NB_H_INCLUDED_H_20230612153121UTC
#define _NB_H_INCLUDED_H_20230612153121UTC

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// 在这里添加你的代码
// ...
#include <stdint.h>
#include <stdio.h>

#define CONFIG_NB_MTU_MAX   1500
#define CONFIG_NB_MAX_PACK  1280

#define nb_log_info printf
#define nb_log_trace printf
#define nb_log_warn printf
#define nb_log_error printf
#define nb_log_fault printf
struct context_t {
    int next_line, first_line;
    uint32_t loop;
};
#define co_begin(ctx) ctx.loop += 1; switch (ctx.next_line) {default: ctx.next_line = ctx.first_line = __LINE__
#define co_yield(ctx, ...) ctx.next_line = __LINE__; return __VA_ARGS__; case __LINE__:
#define co_wait(ctx, signal)
#define co_end(ctx) }
#define co_reset(ctx) ctx.next_line = ctx.first_line

#pragma pack(1)
struct nb_login_t {
    uint8_t mac[6];
    uint8_t group[32];
    uint8_t username[32];
    uint8_t password[32];
};
#pragma pack()

int nb_buff_dump_toggle();
int nb_net_recv_frame(int fd, uint8_t *buff);
int nb_net_send_frame(int fd, uint8_t *buff, int size);
int nb_net_send_pack(int fd, uint8_t *buff, int size);
int nb_net_send_mass(int fd, int mass_size);
int nb_net_send_login(int fd, struct nb_login_t *login, int mass_size);
int net_send_login_ack(int fd, int result, int mass_size);
void nb_dump_buff(const char *title, uint8_t *buff, int size);

#ifdef __cplusplus
};
#endif // __cplusplus
#endif // _NB_H_INCLUDED_H_20230612153121UTC
