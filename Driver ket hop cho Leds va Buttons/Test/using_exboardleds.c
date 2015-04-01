#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <string.h>

#define MAX 7

int main(int argc, char **argv)
{
	int on;
	int led_no;
	int fd;
	if (argc != 3 || sscanf(argv[1], "%d", &led_no) != 1 || sscanf(argv[2],"%d", &on) != 1 ||
	    on < 0 || on > 1 || led_no < 0 || led_no > MAX - 1) {
		fprintf(stderr, "Usage: leds led_no 0|1\n");
		exit(1);
	}
	//Open leds device file
	fd = open("/dev/exboard", 0);
	
	if (fd < 0) {
		perror("error open device leds\n");
		exit(1);
	}
	ioctl(fd, on, led_no);
	close(fd);
	return 0;
}

