kdbus-y	:= main.o ep.o bus.o ns.o resolver.o

obj-$(CONFIG_KDBUS)	+= kdbus.o

obj-m += kdbus.o
obj-m += portal.o

# test programs
hostprogs-y	:= test/test-kdbus portal_test
always		:= $(hostprogs-y)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

TEST_CFLAGS = -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers $(hostprogs-y)
