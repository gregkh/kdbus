kdbus-y	:= \
	bus.o \
	connection.o \
	ep.o \
	main.o \
	match.o \
	message.o \
	names.o \
	notify.o \
	ns.o \
	policy.o

# obj-$(CONFIG_KDBUS)	+= kdbus.o
obj-m += kdbus.o
obj-m += portal.o

# test programs
TEST_COMMON		:= test/kdbus-enum.o test/kdbus-util.o
test-bus-daemon-objs	:= $(TEST_COMMON) test/test-bus-daemon.o
test-kdbus-objs		:= $(TEST_COMMON) test/test-kdbus.o
test-kdbus-fuzz-objs	:= $(TEST_COMMON) test/test-kdbus-fuzz.o
portal_test-objs	:= test/portal_test.o

hostprogs-y		:= test-kdbus test-bus-daemon test-kdbus-fuzz portal_test
always			:= $(hostprogs-y)
HOST_EXTRACFLAGS	+= -std=c99 -Wall -Wextra -g -Wno-unused-parameter -D_GNU_SOURCE

KERNELDIR 		?= /lib/modules/$(shell uname -r)/build
PWD			:= $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers $(hostprogs-y)
	rm -f test/*.o test/.*.cmd
