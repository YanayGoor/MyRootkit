/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.
 *********************************************************************/
#ifndef INCLUDE_PICO_IPC
#define INCLUDE_PICO_IPC
#include "pico_config.h"
#include "pico_device.h"

void ipc_destroy(struct pico_device *ipc);
struct pico_device *ipc_create(const char *sock_path, const char *name, const uint8_t *mac);
struct pico_device *abstract_ipc_create(const char *sock_path, const size_t sock_path_len, const char *name, const uint8_t *mac);

#endif
