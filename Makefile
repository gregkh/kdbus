dbus-y	:= kdbus.o ep.o bus.o ns.o

obj-$(CONFIG_KDBUS)	+= dbus.o


obj-m:= dbus.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build	
PWD       := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers	
