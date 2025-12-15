# Kernel module Makefile
obj-m := packet_filter.o
packet_filter-objs := packet_filter.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
VERSION = 1.0.0

EXTRA_CFLAGS += -I$(src) -DDEBUG -Wall -Wextra

all: kernel userspace

kernel:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

userspace:
	$(MAKE) -C userspace

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	$(MAKE) -C userspace clean
	rm -f *.o *.ko *.mod.c modules.order Module.symvers
	rm -f .*.cmd .*.d

install:
	sudo insmod packet_filter.ko

uninstall:
	sudo rmmod packet_filter

reinstall: uninstall install

test: all
	sudo ./scripts/test_suite.sh

debug: EXTRA_CFLAGS += -DDEBUG -g
debug: all

.PHONY: all kernel userspace clean install uninstall reinstall test debug
