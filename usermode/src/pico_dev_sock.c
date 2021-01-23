/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Authors: Michiel Kustermans
 *********************************************************************/

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "pico_device.h"
#include "pico_dev_sock.h"
#include "pico_stack.h"

#define SOCK_DEV_MTU 2048

static int pico_sock_dev_send(struct pico_device *dev, void *buf, int len)
{
    int res;
    struct pico_device_sock *sdev = (struct pico_device_sock *) dev;
    char *prefixed_buf = PICO_ZALLOC(len + strlen(sdev->prefix));
    strcpy(prefixed_buf, sdev->prefix);
    memcpy(prefixed_buf + strlen(sdev->prefix), buf, len);
    res = (int)write(sdev->fd, prefixed_buf, (uint32_t)(len + strlen(sdev->prefix)));
    PICO_FREE(prefixed_buf);
    return res;
}

static int pico_sock_dev_poll(struct pico_device *dev, int loop_score)
{
    struct pico_device_sock *sdev = (struct pico_device_sock *) dev;
    struct pollfd pfd;
    unsigned char buf[SOCK_DEV_MTU];
    int len;
    pfd.fd = sdev->fd;
    pfd.events = POLLIN;
    do  {
        if (poll(&pfd, 1, 0) <= 0)
            return loop_score;
   

        len = (int)read(sdev->fd, buf, SOCK_DEV_MTU);
        if (len > 0) {
            loop_score--;
            pico_stack_recv(dev, buf + strlen(sdev->prefix), (uint32_t)(len - strlen(sdev->prefix)));
        }
    } while(loop_score > 0);
    return 0;
}

/* Public interface: create/destroy. */

void pico_sock_dev_destroy(struct pico_device *dev)
{
}

struct pico_device *pico_prefixed_sock_dev_create(int sock_fd, const char *prefix, const char *name, const uint8_t *mac) {
    struct pico_device *dev = pico_sock_dev_create(sock_fd, name, mac);
    struct pico_device_sock *sdev = (struct pico_device_sock *) dev;

    if (sdev) {	    
        printf("yes - %ld\n", strlen(prefix));
        sdev->prefix = prefix;
        sdev->dev.mtu = SOCK_DEV_MTU - strlen(prefix);
    }
    return dev;
}


struct pico_device *pico_sock_dev_create(int sock_fd, const char *name, const uint8_t *mac)
{
    struct pico_device_sock *sdev = PICO_ZALLOC(sizeof(struct pico_device_sock));

    if (!sdev || sock_fd < 0)
        return NULL;

    sdev->dev.mtu = SOCK_DEV_MTU;

    if( 0 != pico_device_init((struct pico_device *)sdev, name, mac)) {
        dbg("Sock device init failed.\n");
        return NULL;
    }

    sdev->dev.overhead = 0;
    sdev->fd = sock_fd;
    sdev->prefix = "";
    sdev->dev.send = pico_sock_dev_send;
    sdev->dev.poll = pico_sock_dev_poll;
    sdev->dev.destroy = pico_sock_dev_destroy;
    dbg("Device %s created.\n", sdev->dev.name);
    return (struct pico_device *)sdev;
}
