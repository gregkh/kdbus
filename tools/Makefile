CFLAGS		+= -std=gnu99 -Wall -Wextra -g \
		   -I$(KERNELDIR)/usr/include \
		   -I$(KERNELDIR)/include/uapi \
		   -D_GNU_SOURCE \
		   -Wno-unused-parameter \
		   -Wmaybe-uninitialized \
		   -Wredundant-decls \
		   -Wcast-align \
		   -Wsign-compare \
		   -Wno-missing-field-initializers
CC		:= $(CROSS_COMPILE)gcc

TOOLS = kdbus-monitor

all: $(TOOLS)

%.o: %.c ../kdbus.h
	@echo '  TARGET_CC $@'
	@$(CC) $(CFLAGS) -DKBUILD_MODNAME=\"$(KBUILD_MODNAME)\" -c $< -o $@

kdbus-%: $(TEST_COMMON) kdbus-%.o
	@echo '  TARGET_LD $@'
	@$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean::
	rm -f *.o $(TESTS)
