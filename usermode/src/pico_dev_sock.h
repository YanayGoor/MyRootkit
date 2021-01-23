/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.
 *********************************************************************/
#ifndef INCLUDE_PICO_SOCK_DEV
#define INCLUDE_PICO_SOCK_DEV
#include "pico_config.h"
#include "pico_device.h"

struct pico_device_sock {
    struct pico_device dev;
    int fd;
    const char *prefix;
};

void pico_sock_dev_destroy(struct pico_device *dev);
struct pico_device *pico_sock_dev_create(int sock_fd, const char *name, const uint8_t *mac);
struct pico_device *pico_prefixed_sock_dev_create(int sock_fd, const char *prefix, const char *name, const uint8_t *mac);

#endif
