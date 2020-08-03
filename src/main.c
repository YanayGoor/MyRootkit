#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yanay Goor");
MODULE_DESCRIPTION("Not a rootkit");
MODULE_VERSION("0.1.0");


static int __init MRK_initialize(void) {
	printk(KERN_INFO "Hello, World!\n");
	return 0;
}


static void __exit MRK_exit(void) {
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(MRK_initialize);
module_exit(MRK_exit);
