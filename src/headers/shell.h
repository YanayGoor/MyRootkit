#ifndef SHELL_H
#define SHELL_H

#include "networking.h"

int open_shell(struct open_stream *st);
int recv_shell(struct open_stream *st, char *buff, size_t len);
int close_shell(struct open_stream *st);

#endif