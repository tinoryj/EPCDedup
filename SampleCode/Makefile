
KERNEL_VER = $(shell uname -r)
PWD := $(shell pwd)

# the file to compile
obj-m += KernelHash.o

# specify flags for the module compilation
EXTRA_CFLAGS = -g -O0

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd *.o *.o.d *.cmd *.mod *.mod.c
