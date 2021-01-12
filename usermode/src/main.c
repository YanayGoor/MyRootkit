#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pico.h>

union pipefds {
    struct {
        int read;
        int write;
    };
    int fds[2];
};

int main(int argc, char *argv[]) {
    union pipefds to_child;
    union pipefds from_child;
    char buff[1024];
    size_t size;
    struct pollfd pfd[2]; 
    struct pico_socket *sock;

    int port;
    int dst_port;

    if (argc != 4) {
        printf("Wrong amount of arguments.\n");
        printf("Usage: %s [PORT] [DST_HOST] [DST_PORT]\n", argv[0]);
        return 2;
    }

    port = atoi(argv[1]);
    if (port < 1 || port >> 16) {
        printf("Invalid port\n");
        return 3;
    }

    dst_port = atoi(argv[3]);
    if (dst_port < 1 || dst_port >> 16) {
        printf("Invalid dst port\n");
        return 4;
    }

    sock = create_socket((uint16_t)port, argv[1], (uint16_t)dst_port);

    if (pipe(to_child.fds) == -1) return 1;
    if (pipe(from_child.fds) == -1) return 1;
    
    if (fork()) {
        close(to_child.read);
        close(from_child.write);
        pfd[0] = (struct pollfd) {
            .fd = from_child.read,
            .events = POLLIN,
        };
        pfd[1] = (struct pollfd) {
            .fd = STDOUT_FILENO,
            .events = POLLIN,
        };
        while(1) {
            poll(pfd, 2, 1000);
            if (pfd[0].revents & POLLIN) {
                size = read(from_child.read, buff, 1024);
                fwrite(buff, size, 1, stdout);
            }
            if (pfd[1].revents & POLLIN) {
                size = read(STDIN_FILENO, buff, 1024);
                write(to_child.write, buff, size);
            }
        }
    } else {
        close(to_child.write);
        close(from_child.read);
        dup2(from_child.write, STDOUT_FILENO);
        dup2(from_child.write, STDERR_FILENO);
        dup2(to_child.read, STDIN_FILENO);
        
        execl("/bin/bash","/bin/bash", NULL);
        printf("failed to execl\n");
        return 1;  
    }
    
    return 0;
}