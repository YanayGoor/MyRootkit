#include <stdint.h>

#include <pico_socket.h>
#include <pico_stack.h>
#include <pico_protocol.h>
#include <pico_ipv4.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "pico.h"
#include "utils.h"
#include "pico_dev_ipc.h"
#include "pico_dev_sock.h"

struct pico_socket *sock;
short sock_readable;
short sock_disconnected;

#define CLIENT_ADDR ((struct pico_ip4){.addr=0x01010101})
#define CLIENT_PORT ((uint16_t)1024)
#define SERVER_ADDR ((struct pico_ip4){.addr=0x01010102})
#define SERVER_PORT ((uint16_t)2048)
#define ADDR_MASK ((struct pico_ip4){.addr=0xffffff00})
#define DEV_NAME ("abstract_ipc_device")


void dummy_cb(uint16_t ev, struct pico_socket *s)
{
    mrklog("Sock %ld: recived event %d\n", (long)s, ev);

    if (ev & PICO_SOCK_EV_RD) {
        sock_readable = 1;
    } else if (ev & PICO_SOCK_EV_ERR && pico_err == PICO_ERR_ECONNRESET) {
        sock_disconnected = 1;
    }
}

void init_pico(void) {
    using_color(COLOR_GRAY) {
        pico_stack_init();
    }
}

int create_pico_client(const char *path, size_t path_len) {
    uint16_t local_port = CLIENT_PORT;
    struct pico_ip4 local_addr = CLIENT_ADDR;
    struct pico_ip4 dst_addr = SERVER_ADDR;
    struct pico_device *dev;
    int res;
    int optval = 2900;
    int retryoptval = 3;

    /* create the tap device */
    using_color(COLOR_GRAY) {
        if (!(dev = abstract_ipc_create(path, path_len, DEV_NAME, NULL))) {
            return -1;
        }

        if ((res = pico_ipv4_link_add(dev, CLIENT_ADDR, ADDR_MASK))) {
            goto fail_device;
        }
    }
    mrklog("Pico client: link added.\n");

    if (!(sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &dummy_cb))) {
        goto fail_device;
    }
    mrklog("Pico client: sock opened.\n");

    pico_socket_setoption(sock, PICO_SOCKET_OPT_KEEPIDLE, &optval);
    pico_socket_setoption(sock, PICO_SOCKET_OPT_KEEPINTVL, &optval);
    pico_socket_setoption(sock, PICO_SOCKET_OPT_KEEPCNT, &retryoptval);

    if ((res = pico_socket_bind(sock, &local_addr, &local_port))) {
        goto fail_socket;
    }
    mrklog("Pico client: sock bound.\n");

    if ((res = pico_socket_connect(sock, &dst_addr, SERVER_PORT))) {
        goto fail_socket;
    }
    mrklog("Pico client: sock connected.\n");

    return 0;

fail_socket:
    pico_socket_shutdown(sock, PICO_SHUT_RDWR);

fail_device:
    ipc_destroy(dev);

    mrklog("Pico client: failed with error: %d\n", pico_err);
    return -1;
}

int create_pico_server(int fd, const char *inprefix, const char *outprefix) {
    uint16_t local_port = SERVER_PORT;
    struct pico_ip4 local_addr = SERVER_ADDR;
    struct pico_ip4 other_addr;
    uint16_t other_port;
    struct pico_device *dev;
    struct pico_socket *servsock;
    int res;

    /* create the tap device */
    using_color(COLOR_GRAY) {
        if (!(dev = pico_prefixed_sock_dev_create(fd, inprefix, outprefix, DEV_NAME, NULL))) {
            return -1;
        }

        if ((res = pico_ipv4_link_add(dev, SERVER_ADDR, ADDR_MASK))) {
            goto fail_device;
        }
    }
    mrklog("Pico server: link added.\n");

    if (!(servsock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &dummy_cb))) {
        goto fail_device;
    }
    mrklog("Pico server: sock opened.\n");

    if ((res = pico_socket_bind(servsock, &local_addr, &local_port))) {
        goto fail_socket;
    }
    mrklog("Pico server: sock bound.\n");

    if ((res = pico_socket_listen(servsock, 1))) {
        goto fail_socket;
    }
    mrklog("Pico server: sock listening...\n");

    while (!servsock->number_of_pending_conn) {
        // mrklog("Pico server: awaiting pending connections (currently %d)...\n", servsock->number_of_pending_conn);
        pico_stack_tick();
    }
    mrklog("Pico server: awaiting connection...\n");
    while (!sock) {
        //mrklog("Pico server: awaiting connection...\n");
        sock = pico_socket_accept(servsock, &other_addr, &other_port);
        if (pico_err && pico_err != 11) goto fail_socket;
        pico_stack_tick();
    }
    mrklog("Pico server: sock accepted connection.\n");

    return 0;

fail_socket:
    pico_socket_shutdown(servsock, PICO_SHUT_RDWR);

fail_device:
    ipc_destroy(dev);

    mrklog("Pico server: failed with error: %d\n", pico_err);
    return -1;
}

void tick_pico_stack(void) {
    pico_stack_tick();
}

int pico_sock_write(const void *buf, int len) {
    return pico_socket_write(sock, buf, len);
}

int pico_sock_read(void *buf, int len) {
    if (sock_disconnected) return -1;
    if (!sock_readable) return 0;
    return pico_socket_read(sock, buf, len);
}
