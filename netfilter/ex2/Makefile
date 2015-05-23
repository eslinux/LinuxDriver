TARGET := netfilter2
KROOT = /lib/modules/$(shell uname -r)/build

obj-m += netfilter2.o

all:
	make -C $(KROOT) M=$(shell pwd) modules

clean:
	rm -rf *.o *.ko *mod.c
	

