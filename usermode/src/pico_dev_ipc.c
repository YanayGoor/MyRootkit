/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Authors: Michiel Kustermans
 *********************************************************************/

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "pico_device.h"
#include "pico_stack.h"

#include "pico_dev_ipc.h"
#include "pico_dev_sock.h"

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

static int ipc_connect(const char *sock_path, const size_t sock_path_len)
{
    struct sockaddr_un addr;
    int ipc_fd;

    if((ipc_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
        return(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    memcpy(addr.sun_path, sock_path,  min(sock_path_len, sizeof(addr.sun_path) - 1));
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if(connect(ipc_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) < 0) {
        return(-1);
    }

    return ipc_fd;
}

void ipc_destroy(struct pico_device *dev)
{
    struct pico_device_sock *sdev = (struct pico_device_sock *) dev;
    if(sdev->fd > 0) {
        close(sdev->fd);
    }
}

struct pico_device *ipc_create(const char *sock_path, const char *name, const uint8_t *mac)
{
    const size_t sock_path_len = strlen(sock_path);

    if (!sock_path_len)
        return NULL;

    return abstract_ipc_create(sock_path, sock_path_len, name, mac);
}

struct pico_device *abstract_ipc_create(const char *sock_path, const size_t sock_path_len, const char *name, const uint8_t *mac)
{
    int fd;
    struct pico_device *dev;

    if ((fd = ipc_connect(sock_path, sock_path_len)) < 0) {
        dbg("Ipc creation failed.\n");
        return NULL;
    }

    if (!(dev = pico_sock_dev_create(fd, name, mac))) {
        close(fd);
    }

    return dev;
}