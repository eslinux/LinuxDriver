TARGET := hello_kernel_module
#KROOT = /home/ninhld/freescale/SDK/7420LBV1170/source/linux-3.0.35 source in setenv.sh
KROOT = /lib/modules/$(shell uname -r)/build

obj-m += hello_kernel_module.o

all:
	make -C $(KROOT) M=$(shell pwd) modules

clean:
	rm -rf *.o *.ko *mod.c
	#make -C $(KERNEL_SOURCE) M=$(pwd) clean

install: all
	mkdir -p $(ROOTFS)/opt/driver
	cp -rf $(TARGET).ko $(ROOTFS)/opt/driver
