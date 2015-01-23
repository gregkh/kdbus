kdbus$(EXT)-y := \
	bus.o \
	connection.o \
	endpoint.o \
	fs.o \
	handle.o \
	item.o \
	main.o \
	match.o \
	message.o \
	metadata.o \
	names.o \
	node.o \
	notify.o \
	domain.o \
	policy.o \
	pool.o \
	queue.o \
	reply.o \
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
	test/kdbus-test

mandoc:	
	$(MAKE) -C doc mandoc

doc:	mandoc

kerneldoc_check:
	$(KERNELDIR)/scripts/kernel-doc *.c kdbus.h >/dev/null | grep "^Warning"

install: module
	mkdir -p /lib/modules/$(KERNELVER)/kernel/ipc/kdbus$(EXT)/
	cp -f kdbus$(EXT).ko /lib/modules/$(KERNELVER)/kernel/ipc/kdbus$(EXT)/
	depmod $(KERNELVER)

uninstall:
	rm -f /lib/modules/$(KERNELVER)/kernel/ipc/kdbus/kdbus$(EXT).ko
	rm -f /lib/modules/$(KERNELVER)/kernel/drivers/kdbus/kdbus$(EXT).ko
	rm -f /lib/modules/$(KERNELVER)/kernel/drivers/misc/kdbus/kdbus$(EXT).ko

coccicheck:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) coccicheck

tt-prepare: module test
	-sudo sh -c 'dmesg -c > /dev/null'
	-sudo umount /sys/fs/kdbus$(EXT)
	-sudo sh -c 'rmmod kdbus$(EXT)'
	sudo sh -c 'insmod kdbus$(EXT).ko attach_flags_mask=0xffffffffffffffff'
	sudo mount -t kdbus$(EXT)fs kdbus$(EXT)fs /sys/fs/kdbus$(EXT)

tt: tt-prepare
	test/kdbus-test -m kdbus$(EXT)
	dmesg

stt: tt-prepare
	sudo test/kdbus-test -m kdbus$(EXT)
	dmesg
