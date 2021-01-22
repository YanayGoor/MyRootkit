#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include "pico.h"
#include "utils.h"

#define SOCK_PATH ("\0test-file2")
#define SOCK_PATH_LEN (sizeof(SOCK_PATH))

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

static int ipc_connect(int ipc_fd, const char *sock_path, const size_t sock_path_len)
{
    struct sockaddr_un addr;
    size_t addr_len = min(sock_path_len, sizeof(addr.sun_path) - 1);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    memcpy(addr.sun_path, sock_path, addr_len);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if(bind(ipc_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) < 0) {
        return 1;
    }

    return 0;
}

int main() {
    int err;
    int srvsock;
    int sock;
    struct pollfd pfd[1];
    size_t size;
    char buff[1024];

    init_pico();

    if ((srvsock = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
        return 1;
    }
    mrklog("unix sock created\n");

    if (ipc_connect(srvsock, SOCK_PATH, SOCK_PATH_LEN)) {
        return 1;
    }
    mrklog("unix sock bound\n");

    if (listen(srvsock, 1) < 0) {
        return 1;
    }
    mrklog("unix sock listening\n");

    if ((sock = accept(srvsock, NULL, NULL)) < 0) {
        return 1;
    }
    mrklog("unix sock accepted connection\n");

    if ((err = create_pico_server(sock))) {
        printf("result: %d\nerrno: %d\n", err, errno);
        return 1;
    }
    mrklog("server created \n");
    mrklogcrit("Bash is open, start doing stuff..\n");


    pfd[0] = (struct pollfd) {
        .fd = STDIN_FILENO,
        .events = POLLIN,
    };

    while(1) {
        tick_pico_stack();
        poll(pfd, 1, 100);
        if (pfd[0].revents & POLLIN) {
            size = read(STDIN_FILENO, buff, 1024);
            // fwrite(buff, size, 1, stdout);
            size = pico_sock_write(buff, size);
            mrklog("wrote %ld bytes to sock..\n", size);            
        }
        size = pico_sock_read(buff, 1024);
        if (size) {
            fwrite(buff, size, 1, stdout);
        }
    }

    return 0;
}