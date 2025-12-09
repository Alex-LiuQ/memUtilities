# File: Makefile
# Target: Cross-compile shared library and executables for ARM64 OpenWrt
# Description: This Makefile cross-compiles a shared library (libmalloc_hook.so)
#              and several executables for ARM64 OpenWrt using the specified
#              cross-compiler toolchain.
CROSS_COMPILE ?= aarch64-openwrt-linux-musl-
CC            := $(CROSS_COMPILE)gcc
LD            := $(CROSS_COMPILE)ld
AR            := $(CROSS_COMPILE)ar

# Compiler and linker flags
CFLAGS  := -O2 -Wall -fPIC
LDFLAGS := -shared
LDLIBS  := -ldl -lpthread -ldl

# If you need headers/libraries from staging_dir in the future, you can add them here (not necessary now)
# STAGING_DIR ?=
# ifneq ($(STAGING_DIR),)
# CFLAGS  += -I$(STAGING_DIR)/usr/include
# LDFLAGS += -L$(STAGING_DIR)/usr/lib
# endif

# ====================== Targets ======================
# 1. Shared library
# 2. User 'LD_PRELOAD=./libmalloc_hook.so XXXX' to load the shared library and to safely hook malloc/free calls
SO_TARGETS := libmalloc_hook.so

# 2. Executables (all .c files automatically generate executables with the same name, excluding malloc_hook.c)
EXEC_SRCS := $(filter-out malloc_hook.c, $(wildcard *.c))
EXEC_TARGETS := $(patsubst %.c,%,$(EXEC_SRCS))

# All targets to be built
ALL_TARGETS := $(SO_TARGETS) $(EXEC_TARGETS)

# ====================== Default target ======================
all: $(ALL_TARGETS)
	@echo "=== All build complete ==="
	@ls -lh $(ALL_TARGETS)

# ====================== Shared library rules ======================
$(SO_TARGETS): malloc_hook.c
	@echo "Building shared library $@ ..."
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# ====================== Executable rules ======================
$(EXEC_TARGETS): %: %.c
	@echo "Building executable $@ ..."
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# ====================== Common phony targets ======================
.PHONY: clean run_leak run_memlogger run_test

clean:
	rm -f $(ALL_TARGETS) *.o *.so.* *.gdb *.log

# Quick run common test programs (convenient)
run_leak: leak_test
	LD_PRELOAD=./libmalloc_hook.so ./leak_test

run_memlogger: memlogger
	./memlogger

run_test: test_malloc_hook
	LD_PRELOAD=./libmalloc_hook.so ./test_malloc_hook

# ===================== Additional info targets ======================
test: run_leak
	@echo "leak_test completed, view logs:"
	@cat /var/memhook.log 2>/dev/null || cat /tmp/memhook.log 2>/dev/null || echo "No log files found"

info:
	@echo "Executables  :" $(EXEC_TARGETS)
	@echo "Shared library:" $(SO_TARGETS)
