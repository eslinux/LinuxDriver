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
#include <linux/poll.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/sched.h>


#define DEVICE_NAME "exboard"
#define MAX 	7

/////////////////////////////////////////////////////////////////////////
//
//LEDS
//
//
//
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

///////////////////////////////////////////////////////////////////////////////////////
//
//BUTTONS
//
//
//
struct button_irq_desc {
	int irq;
	int pin;
	int pin_setting;
	int number;
	char *name;
};

static struct button_irq_desc button_irqs [] = {
{IRQ_EINT0, S3C2410_GPF(0) ,  S3C2410_GPF0_EINT0 , 0, "KEY0"},
{IRQ_EINT1, S3C2410_GPF(1) ,  S3C2410_GPF1_EINT1 , 1, "KEY1"},
{IRQ_EINT2, S3C2410_GPF(2) ,  S3C2410_GPF2_EINT2 , 2, "KEY2"},
{IRQ_EINT3, S3C2410_GPF(3) ,  S3C2410_GPF3_EINT3 , 3, "KEY3"},
{IRQ_EINT4, S3C2410_GPF(4) ,  S3C2410_GPF4_EINT4 , 4, "KEY4"},
{IRQ_EINT5, S3C2410_GPF(5) ,  S3C2410_GPF5_EINT5 , 5, "KEY5"},
{IRQ_EINT6, S3C2410_GPF(6) ,  S3C2410_GPF6_EINT6 , 6, "KEY6"},
};

static volatile char key_values [] = {'0', '0', '0', '0', '0', '0', '0'};

static DECLARE_WAIT_QUEUE_HEAD(button_waitq);

static volatile int ev_press = 0;

// Implementation of the ioctl
static int sbc2440_gpf0_ioctl(struct inode *inode, struct file *file,
							  unsigned int cmd, unsigned long arg)
{
	int i;
	
	for (i = 0; i < MAX; i++) {
		s3c2410_gpio_cfgpin(led_table[i], led_cfg_table[i]);
		s3c2410_gpio_setpin(led_table[i], 0);
	}
	switch(cmd) //Switch the value of cmd.
		// If Cmd = 0 we put the pin to 0. If Cmd = 1,we put the pin 1.
	{
	case 0:
	case 1:
		if (arg > MAX - 1 )
		{
			return -EINVAL;
		}
		s3c2410_gpio_cfgpin(led_table[arg], led_cfg_table[arg]);
		s3c2410_gpio_setpin(led_table[arg], !cmd); // Change the state of the pin
		return 0;
	default:
		return -EINVAL;
	}
}




static irqreturn_t buttons_interrupt(int irq, void *dev_id)
{
	struct button_irq_desc *button_irqs = (struct button_irq_desc *)dev_id;
	int down;

	// udelay(0);
	down = !s3c2410_gpio_getpin(button_irqs->pin);

	if (down != (key_values[button_irqs->number] & 1)) { // Changed

		key_values[button_irqs->number] = '0' + down;

		ev_press = 1;
		wake_up_interruptible(&button_waitq);
	}

	return IRQ_RETVAL(IRQ_HANDLED);
}


static int s3c24xx_buttons_open(struct inode *inode, struct file *file)
{
	int i;
	int err = 0;

	for (i = 0; i < sizeof(button_irqs)/sizeof(button_irqs[0]); i++) {
		if (button_irqs[i].irq < 0) {
			continue;
		}
		err = request_irq(button_irqs[i].irq, buttons_interrupt, IRQ_TYPE_EDGE_BOTH,
						  button_irqs[i].name, (void *)&button_irqs[i]);
		if (err)
			break;
	}

	if (err) {
		i--;
		for (; i >= 0; i--) {
			if (button_irqs[i].irq < 0) {
				continue;
			}
			disable_irq(button_irqs[i].irq);
			free_irq(button_irqs[i].irq, (void *)&button_irqs[i]);
		}
		return -EBUSY;
	}

	ev_press = 1;

	return 0;
}


static int s3c24xx_buttons_close(struct inode *inode, struct file *file)
{
	int i;

	for (i = 0; i < sizeof(button_irqs)/sizeof(button_irqs[0]); i++) {
		if (button_irqs[i].irq < 0) {
			continue;
		}
		free_irq(button_irqs[i].irq, (void *)&button_irqs[i]);
	}

	return 0;
}


static int s3c24xx_buttons_read(struct file *filp, char __user *buff, size_t count, loff_t *offp)
{
	unsigned long err;

	if (!ev_press) {
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		else
			wait_event_interruptible(button_waitq, ev_press);
	}

	ev_press = 0;

	err = copy_to_user(buff, (const void *)key_values, min(sizeof(key_values), count));

	return err ? -EFAULT : min(sizeof(key_values), count);
}

static unsigned int s3c24xx_buttons_poll( struct file *file, struct poll_table_struct *wait)
{
	unsigned int mask = 0;
	poll_wait(file, &button_waitq, wait);
	if (ev_press)
		mask |= POLLIN | POLLRDNORM;
	return mask;
}

// The structure that contains pointers to 
// functions defined in the module that perform read-write operations ...
static struct file_operations dev_fops = {
	.owner	 = THIS_MODULE,
	.ioctl 	 = sbc2440_gpf0_ioctl,
	.open    =   s3c24xx_buttons_open,
	.release =   s3c24xx_buttons_close,
	.read    =   s3c24xx_buttons_read,
	.poll    =   s3c24xx_buttons_poll,
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

