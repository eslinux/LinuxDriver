#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/ioctl.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/select.h>
#include<sys/time.h>
#include<errno.h>

//	insmod hello_driver.ko
//	mknod /dev/KTMT0 c 250 1
//	./app_hello_driver /dev/KTMT0


int main(int argc, char** argv)
{
	int fd;
	int result,rt;
	fd = open(argv[1], 0);
	rt=read(fd,&result,sizeof(result));
	printf("\nKet qua nha ve la %d\n",rt);
	close(fd);

	return 0;
}
