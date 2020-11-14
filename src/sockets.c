#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/list.h>

#include "headers/networking.h"

#include "socket/af_packet_internal.h"
#include "socket/packet_hook.h"
#include "socket/hook.h"

int hooked_wake_up(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key) {
    unsigned long _flags;
    struct socket *sock = (struct socket *)wq_entry->private;
    
    if (is_packet_sock(sock)) {
        spin_lock_irqsave(&hook_packet_lock, _flags);
        hook_packet_sock(sock);
	    spin_unlock_irqrestore(&hook_packet_lock, _flags);
    } else {
        list_del_init(&wq_entry->entry);
    }
    return 0;
}

struct unhooked_socket_entry {
    struct list_head head;
    struct socket *sock;
};

static LIST_HEAD(unhooked_sockets);

static struct inode *(*original_alloc_inode)(struct super_block *sb);

static struct inode *hooked_alloc_inode(struct super_block *sb) {
    struct inode *res;
    struct socket *sock;
    struct wait_queue_entry *wq;
    struct unhooked_socket_entry *s_entry;

    res = original_alloc_inode(sb);
    sock = SOCKET_I(res);

    /* Add wait queue entry */
    wq = kmalloc(sizeof(struct wait_queue_entry), GFP_KERNEL);
    init_waitqueue_func_entry(wq, &hooked_wake_up);
    wq->private = sock;
    add_wait_queue(&sock->wq.wait, wq);

    /* Add to unhooked queue */
    s_entry = kmalloc(sizeof(struct unhooked_socket_entry), GFP_KERNEL);
    s_entry->sock = sock;
    list_add_tail(&s_entry->head, &unhooked_sockets);

    return res;
}

static DEFINE_SPINLOCK(unhooked_sockets_lock);

static int hooked_d_init(struct dentry *dentry)
{
    struct unhooked_socket_entry *s_entry;
    struct unhooked_socket_entry *temp;
    unsigned long flags;
    unsigned long flags2;

    /* Handle unhooked queue */
    spin_lock_irqsave(&unhooked_sockets_lock, flags2);
	list_for_each_entry_safe(s_entry, temp, &unhooked_sockets, head) {
        // TODO: Only do this if the socket is ready to patch (it has ops and recv function.)
        spin_lock_irqsave(&hook_packet_lock, flags);
        if (is_packet_sock(s_entry->sock)) {
            hook_packet_sock(s_entry->sock);
        }
        list_del(&s_entry->head);
        kfree(s_entry);
        spin_unlock_irqrestore(&hook_packet_lock, flags);
    }
    spin_unlock_irqrestore(&unhooked_sockets_lock, flags2);
	return 0;
}

int MRK_init_sockets_hook(void) {
    struct file_system_type *fs_type;
    struct super_block *super;
    struct super_operations *s_op;
    struct dentry_operations *s_d_op;

    hook_init();

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
}
