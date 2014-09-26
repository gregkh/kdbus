ifeq ($(strip $(V)), 1)
  Q =
else
  Q = @
endif

CFLAGS		+= -std=gnu99 -Wall -Wextra -g \
		   -include $(KERNELDIR)/include/uapi/linux/memfd.h \
		   -include $(KERNELDIR)/include/uapi/asm-generic/unistd.h \
		   -D_GNU_SOURCE \
		   -Wno-unused-parameter \
		   -Wmaybe-uninitialized \
		   -Wredundant-decls \
		   -Wcast-align \
		   -Wsign-compare \
		   -Wno-missing-field-initializers
LDFLAGS		:= -pthread -lcap
CC		:= $(CROSS_COMPILE)gcc

OBJS= \
	kdbus-enum.o		\
	kdbus-util.o		\
	kdbus-test.o		\
	test-activator.o	\
	test-benchmark.o	\
	test-chat.o		\
	test-connection.o	\
	test-daemon.o		\
	test-domain.o		\
	test-fd.o		\
	test-free.o		\
	test-match.o		\
	test-message.o		\
	test-metadata-ns.o	\
	test-monitor.o		\
	test-names.o		\
	test-policy.o		\
	test-policy-ns.o	\
	test-policy-priv.o	\
	test-race.o		\
	test-sync.o		\
	test-timeout.o

all: kdbus-test

%.o: %.c ../kdbus.h
	@echo '  TARGET_CC $@'
	$(Q)$(CC) $(CFLAGS) -DKBUILD_MODNAME=\"$(KBUILD_MODNAME)\" -c $< -o $@

kdbus-test: $(OBJS)
	@echo '  TARGET_LD $@'
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean::
	rm -f *.o $(TESTS)
