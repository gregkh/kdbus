kdbus-y	:= main.o ep.o bus.o ns.o resolver.o

obj-$(CONFIG_KDBUS)	+= kdbus.o

obj-m:= kdbus.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

TEST_CFLAGS = -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
TEST_SRC = test/test-kdbus.c

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)
	gcc $(TEST_CFLAGS) -I$(KERNELDIR)/include/ -o test-kdbus $(TEST_SRC)

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers	
