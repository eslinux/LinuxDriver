#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>


static int hello_init(void)
{	
    printk(KERN_ALERT "Khoi tao thanh cong\n");
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_ALERT "Ket thuc thanh cong\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NINHLD");
MODULE_VERSION("1.0.0");


