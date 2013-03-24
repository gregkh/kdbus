kdbus-y	:= main.o ep.o bus.o ns.o resolver.o

obj-$(CONFIG_KDBUS)	+= kdbus.o

obj-m:= kdbus.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build	
PWD       := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers	
