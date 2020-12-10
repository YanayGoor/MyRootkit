#ifndef NETWORKING_H
#define NETWORKING_H

#include <linux/skbuff.h>

int MRK_init_nethook(void);
int MRK_exit_nethook(void);

int is_skb_cmd(struct sk_buff *skb);

#endif /* NETWORKING_H */
