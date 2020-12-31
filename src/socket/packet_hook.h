#ifndef PACKET_HOOK_H

int is_packet_sock(struct socket *sock);
void hook_packet_sock(struct socket *sock);

#define PACKET_HOOK_H
#endif // PACKET_HOOK_H