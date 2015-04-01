#include <linux/miscdevice.h>
#include <linux/delay.h>
#include <asm/irq.h>
#include <mach/regs-gpio.h>
#include <mach/hardware.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/gpio.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <asm/unistd.h>
#include <linux/sched.h>



#define DEVICE_NAME "GPFxLeds"
#define MAX 	7

static unsigned long led_table [] = {
	S3C2410_GPF(0),
	S3C2410_GPF(1),
	S3C2410_GPF(2),
	S3C2410_GPF(3),
	S3C2410_GPF(4),
	S3C2410_GPF(5),
	S3C2410_GPF(6)
};

static unsigned int led_cfg_table [] = {
	S3C2410_GPIO_OUTPUT,
	S3C2410_GPIO_OUTPUT,
	S3C2410_GPIO_OUTPUT,
	S3C2410_GPIO_OUTPUT,
	S3C2410_GPIO_OUTPUT,
	S3C2410_GPIO_OUTPUT,
	S3C2410_GPIO_OUTPUT
};

// Implementation of the ioctl
static int sbc2440_gpf0_ioctl(struct inode *inode, struct file *file,
							  unsigned int cmd, unsigned long arg)
{
	switch(cmd) //Switch the value of cmd.
		// If Cmd = 0 we put the pin to 0. If Cmd = 1,we put the pin 1.
	{
	case 0:
	case 1:
		if (arg > MAX - 1 )
		{
			return -EINVAL;
		}
		s3c2410_gpio_setpin(led_table[arg], !cmd); // Change the state of the pin
		return 0;
	default:
		return -EINVAL;
	}
}

// The structure that contains pointers to 
// functions defined in the module that perform read-write operations ...
static struct file_operations dev_fops = {
	.owner = THIS_MODULE,
	.ioctl = sbc2440_gpf0_ioctl
};

static struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &dev_fops
};

static int __init dev_init(void)
{
	int ret;
	// Function init
	int i;
	
	for (i = 0; i < MAX; i++) {
		s3c2410_gpio_cfgpin(led_table[i], led_cfg_table[i]);
		s3c2410_gpio_setpin(led_table[i], 0);
	}
	
	ret = misc_register(&misc);

	printk (DEVICE_NAME"\tInitialized\n");

	return ret;
}
static void __exit dev_exit(void)
{
	// Function exit
	misc_deregister(&misc);
}

module_init(dev_init);
module_exit(dev_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("TH");

