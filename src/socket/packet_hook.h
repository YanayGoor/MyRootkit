#ifndef PACKET_HOOK_H

int is_packet_sock(struct socket *sock);
void hook_packet_sock(struct socket *sock);

static DEFINE_SPINLOCK(hook_packet_lock);

#define PACKET_HOOK_H
#endif // PACKET_HOOK_H