#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/kfifo.h>

#include "headers/networking.h"

#include "socket/af_packet_internal.h"
#include "socket/packet_hook.h"
#include "socket/hook.h"

int hooked_wake_up(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key) {
    struct socket *sock = (struct socket *)wq_entry->private;
    
    if (is_packet_sock(sock)) {
        hook_packet_sock(sock);
    } else {
        list_del_init(&wq_entry->entry);
    }
    return 0;
}

#define FIFO_SIZE 32

static DECLARE_KFIFO(unhooked_sockets, struct socket *, FIFO_SIZE);
static DEFINE_SPINLOCK(read_lock);
static DEFINE_SPINLOCK(write_lock);

static struct inode *(*original_alloc_inode)(struct super_block *sb);

static struct inode *hooked_alloc_inode(struct super_block *sb) {
    struct inode *res;
    struct socket *sock;
    unsigned long flags;
    struct wait_queue_entry *wq;

    res = original_alloc_inode(sb);
    sock = SOCKET_I(res);

    /* Add wait queue entry */
    wq = kmalloc(sizeof(struct wait_queue_entry), GFP_KERNEL);
    init_waitqueue_func_entry(wq, &hooked_wake_up);
    wq->private = sock;
    add_wait_queue(&sock->wq.wait, wq);

    /* Add to unhooked queue */
    spin_lock_irqsave(&write_lock, flags);
    kfifo_put(&unhooked_sockets, sock);
    spin_unlock_irqrestore(&write_lock, flags);
    return res;
}


static int hooked_d_init(struct dentry *dentry)
{
    struct socket *sock;
    unsigned long flags;
    int res;

    /* Handle unhooked queue */
    while (!kfifo_is_empty(&unhooked_sockets)) {
        spin_lock_irqsave(&read_lock, flags);
        res = kfifo_get(&unhooked_sockets, &sock);
        spin_unlock_irqrestore(&read_lock, flags);
        if (!res) break;

        // TODO: Only do this if the socket is ready to patch (it has ops and recv function.)
        if (is_packet_sock(sock)) {
            hook_packet_sock(sock);
        }
    }	
	return 0;
}

int MRK_init_sockets_hook(void) {
    struct file_system_type *fs_type;
    struct super_block *super;
    struct super_operations *s_op;
    struct dentry_operations *s_d_op;

    hook_init();
    INIT_KFIFO(unhooked_sockets);

    fs_type = get_fs_type("sockfs");

    hlist_for_each_entry(super, &fs_type->fs_supers, s_instances) {
        s_op = (struct super_operations *)kmalloc(sizeof(struct super_operations), GFP_KERNEL);
        memcpy(s_op, super->s_op, sizeof(struct super_operations));
        super->s_op = s_op;
        original_alloc_inode = s_op->alloc_inode;
        s_op->alloc_inode = &hooked_alloc_inode;

        s_d_op = (struct dentry_operations *)kmalloc(sizeof(struct dentry_operations), GFP_KERNEL);
        memcpy(s_d_op, super->s_d_op, sizeof(struct dentry_operations));
        super->s_d_op = s_d_op;
        
        s_d_op->d_init = &hooked_d_init;
    }
    return 0;
}

void MRK_exit_sockets_hook(void) {
    kfifo_free(&unhooked_sockets);
}
