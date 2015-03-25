TARGET := centic-crypto
KERNEL_SOURCE = /home/ninhld/freescale/SDK/7420LBV1170/source/linux-3.0.35

obj-m += centic-crypto.o

all:
	make -C $(KERNEL_SOURCE) M=$(shell pwd) modules
	#make -C ./TestApp

clean:
	make -C $(KERNEL_SOURCE) M=$(pwd) clean
	#make -C ./TestApp clean
