kdbus-y	:= \
	bus.o \
	connection.o \
	pool.o \
	memfd.o \
	endpoint.o \
	main.o \
	match.o \
	message.o \
	metadata.o \
	names.o \
	notify.o \
	namespace.o \
	policy.o

# obj-$(CONFIG_KDBUS)	+= kdbus.o
obj-m += kdbus.o

KERNELDIR 		?= /lib/modules/$(shell uname -r)/build
PWD			:= $(shell pwd)

all: module test

test::
	$(MAKE) -C test

module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

coccicheck:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) coccicheck

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers $(hostprogs-y)
	$(MAKE) -C test clean

tt: all
	sudo sh -c 'dmesg -c > /dev/null'
	sudo sh -c 'rmmod kdbus'
	sudo sh -c 'insmod kdbus.ko'
	-sudo sh -c 'sync; umount / 2> /dev/null'
	test/test-kdbus
