#ifndef NETWORKING_H
#define NETWORKING_H

#include <linux/skbuff.h>

int MRK_init_nethook(void);
void MRK_exit_nethook(void);

int is_skb_cmd(struct sk_buff *skb);

typedef u16 job_id_t;

struct origin {
    job_id_t job_id;
    __be32 remote_addr;
    __be32 local_addr;
    __be16 remote_port;
    unsigned char remote_mac[ETH_ALEN];
    struct net_device *dev;
};

struct open_stream;

struct stream_type {
    int (*open)(struct open_stream *st);
    int (*recv)(struct open_stream *st, char *buff, size_t len);
    int (*close)(struct open_stream *st);
};

struct open_stream {
    struct hlist_node node;
    struct origin origin;
    struct stream_type type;
    void *data;
};

int send_response(
    struct origin origin,
    char *response,
    size_t response_len
);

void close_stream(struct open_stream *stream);

#endif /* NETWORKING_H */
