#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/fs.h>

static ssize_t hello_read(struct file *filp, char *buffer, size_t length, loff_t *offset);
static int Major;
//Cấu trúc để đăng ký các hàm qua driver interface được được qui định theo chuẩn
static struct file_operations fops={
	.owner=THIS_MODULE,
	.read=hello_read,
};

static int hello_init(void)
{
	//Đăng ký thiết bị kiểu character với major id hệ thống cung cấp

	Major=register_chrdev(0,"KTMT­Device",&fops);
	if(Major<0)
	{
		printk(KERN_ALERT "Dang ky that bai\n");
	}
	else{
		printk(KERN_ALERT "Dang ky thiet bi thanh cong voi MajorID=%d\n",Major);
	}
	
	return 0;
}


static void hello_exit(void)
{
	//Giải phóng thiết bị đã đăng ký
	unregister_chrdev(Major,"KTMT­Device");
	printk(KERN_ALERT "Thiet bi da bi ngat khoi he thong\n");
}
//Hàm read được cung cấp qua driver interface
static ssize_t hello_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	return 100; //Hảm read của driver chỉ đơn giản trả về một giá trị

}


module_init(hello_init);
module_exit(hello_exit);
