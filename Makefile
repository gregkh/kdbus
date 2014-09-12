kdbus$(EXT)-y := \
	bus.o \
	connection.o \
	endpoint.o \
	handle.o \
	main.o \
	match.o \
	message.o \
	metadata.o \
	names.o \
	notify.o \
	domain.o \
	policy.o \
	pool.o \
	queue.o \
	util.o

obj-m += kdbus$(EXT).o

KERNELVER		?= $(shell uname -r)
KERNELDIR 		?= /lib/modules/$(KERNELVER)/build
PWD			:= $(shell pwd)

all: module tools test

tools::
	$(MAKE) -C tools KERNELDIR=$(realpath $(KERNELDIR)) KBUILD_MODNAME=kdbus$(EXT)

test::
	$(MAKE) -C test KERNELDIR=$(realpath $(KERNELDIR)) KBUILD_MODNAME=kdbus$(EXT)

module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers $(hostprogs-y)
	$(MAKE) -C test clean

check:
	test/test-kdbus

install: module
	mkdir -p /lib/modules/$(KERNELVER)/kernel/drivers/kdbus$(EXT)/
	cp -f kdbus$(EXT).ko /lib/modules/$(KERNELVER)/kernel/drivers/kdbus$(EXT)/
	depmod $(KERNELVER)

uninstall:
	rm -f /lib/modules/$(KERNELVER)/kernel/drivers/kdbus/kdbus$(EXT).ko

coccicheck:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) coccicheck

tt: all
	sudo sh -c 'dmesg -c > /dev/null'
	-sudo sh -c 'rmmod kdbus$(EXT)'
	sudo sh -c 'insmod kdbus$(EXT).ko'
	-sudo sh -c 'sync; umount / 2> /dev/null'
	test/test-kdbus
	dmesg
