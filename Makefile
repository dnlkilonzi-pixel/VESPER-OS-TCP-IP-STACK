# Makefile - VESPER OS TCP/IP Stack
#
# Builds the network stack as a static library (libnet.a) and a
# host-native test binary so the code can be validated on Linux without
# a full OS boot.
#
# Targets:
#   make            - build the static library and test binary
#   make test       - compile and run the unit tests (native, no QEMU)
#   make clean      - remove all build artefacts
#   make kernel.elf - link everything into a bare-metal ELF (cross-compile)
#
# Toolchain selection:
#   Native (default): uses the host gcc/ar — suitable for unit testing only.
#   Cross (CROSS=1):  uses i686-elf-gcc — for actual bare-metal builds.
#     Install with: apt-get install gcc-i686-linux-gnu  (or build from source)

# ------------------------------------------------------------------- #
# Toolchain                                                            #
# ------------------------------------------------------------------- #

ifdef CROSS
    CC      = i686-elf-gcc
    AR      = i686-elf-ar
    CFLAGS  = -std=c99 -Wall -Wextra -ffreestanding -O2 \
              -fno-stack-protector -fno-builtin \
              -I$(INCDIR)
    LDFLAGS = -ffreestanding -nostdlib -lgcc
else
    CC      = gcc
    AR      = ar
    CFLAGS  = -std=c99 -Wall -Wextra -O2 \
              -DTEST_HOST \
              -I$(INCDIR)
    LDFLAGS =
endif

# ------------------------------------------------------------------- #
# Directory layout                                                     #
# ------------------------------------------------------------------- #

INCDIR   = include
BUILDDIR = build

ETHERNET_SRC = ethernet/ethernet.c
IP_SRC       = ip/ip.c
TCP_SRC      = tcp/tcp.c
DRIVER_SRC   = drivers/nic_stub.c
NET_SRC      = net/net.c net/klog.c

LIB_SRCS = $(ETHERNET_SRC) $(IP_SRC) $(TCP_SRC) $(DRIVER_SRC) $(NET_SRC)
LIB_OBJS = $(patsubst %.c,$(BUILDDIR)/%.o,$(LIB_SRCS))

TEST_SRCS = tests/test_main.c tests/test_ethernet.c tests/test_ip.c \
            tests/test_tcp.c
TEST_OBJS = $(patsubst %.c,$(BUILDDIR)/%.o,$(TEST_SRCS))

LIB      = $(BUILDDIR)/libnet.a
TEST_BIN = $(BUILDDIR)/run_tests

# ------------------------------------------------------------------- #
# Default target                                                       #
# ------------------------------------------------------------------- #

.PHONY: all test clean

all: $(LIB) $(TEST_BIN)

# ------------------------------------------------------------------- #
# Static library                                                       #
# ------------------------------------------------------------------- #

$(LIB): $(LIB_OBJS)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^
	@echo "  AR   $@"

# ------------------------------------------------------------------- #
# Test binary                                                          #
# ------------------------------------------------------------------- #

$(TEST_BIN): $(TEST_OBJS) $(LIB)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB) $(LDFLAGS)
	@echo "  LD   $@"

# ------------------------------------------------------------------- #
# Bare-metal kernel ELF (cross-compile only)                          #
# ------------------------------------------------------------------- #

KERNEL_OBJ = $(BUILDDIR)/main.o
kernel.elf: $(KERNEL_OBJ) $(LIB)
	$(CC) $(LDFLAGS) -T linker.ld -o $@ $^
	@echo "  LD   $@"

# ------------------------------------------------------------------- #
# Generic compilation rule                                             #
# ------------------------------------------------------------------- #

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  CC   $<"

# ------------------------------------------------------------------- #
# Test target                                                          #
# ------------------------------------------------------------------- #

test: $(TEST_BIN)
	@echo "Running VESPER OS network stack unit tests..."
	./$(TEST_BIN)

# ------------------------------------------------------------------- #
# Clean                                                                #
# ------------------------------------------------------------------- #

clean:
	rm -rf $(BUILDDIR) kernel.elf
	@echo "  CLEAN"
