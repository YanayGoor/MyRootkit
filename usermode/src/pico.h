#include <stdint.h>

#ifndef PICO_H
#define PICO_H

void init_pico();

int create_pico_client();
int create_pico_server();

void tick_pico_stack(void);
int pico_sock_write(const void *buf, int len);
int pico_sock_read(void *buf, int len);

#endif