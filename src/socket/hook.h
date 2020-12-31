#ifndef HOOK_H

#include <linux/hashtable.h>

struct hooked_socket_entry {
    struct hlist_node node;
    struct hlist_node prot_hook_node;
    struct socket *sock;
    const struct proto_ops *original_packet_ops;
    int (*original_packet_rcv)(struct sk_buff *skb, struct net_device *dev,
		                       struct packet_type *pt, struct net_device *orig_dev);
};

struct hooked_socket_entry *get_socket_hook(struct socket *sock);
struct hooked_socket_entry *get_socket_hook_by_prot_hook(struct packet_type *pt);

struct hooked_socket_entry *get_or_create_socket_hook(struct socket *sock, struct proto_ops **hooked_ops);

int hook_init(void);
void hook_exit(void);

#define HOOK_H
#endif // HOOK_H