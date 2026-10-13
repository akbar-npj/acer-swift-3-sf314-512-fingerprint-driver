# Clean-room reimplementation of the FPC e340 BEP algorithm.
#
# x86-64 only: the vendor code is Microsoft-ABI (ms_abi) and the difftest calls
# it directly, so this cannot build on aarch64.
#
#   make            build libfpcbep.a and the difftest harness
#   make check      build + run the differential test against fpc_enclave.dll
#   make clean

CC      ?= cc
NATIVE  := ../native
INCS    := -Iinclude -I$(NATIVE)

# -ffp-contract=off is REQUIRED: it stops gcc fusing mul+add into an FMA, which
# would change the rounding and break bit-for-bit parity with the vendor code.
CFLAGS  ?= -O2 -g -Wall -Wextra -ffp-contract=off -fno-strict-aliasing
LDFLAGS ?= -lpthread

SRC     := src/fpc_math.c src/fpc_buffer.c src/fpc_util.c src/fpc_image.c \
           src/fpc_rect.c src/fpc_bitmap.c src/fpc_copy.c src/fpc_affine.c \
           src/fpc_stats.c src/fpc_filter.c src/fpc_orient.c src/fpc_matmul.c \
           src/fpc_sample.c src/fpc_alloc.c src/fpc_transform.c src/fpc_grid.c \
           src/fpc_desc.c src/fpc_sort.c src/fpc_linefit.c src/fpc_tree.c
OBJ     := $(SRC:.c=.o)

DLL     := ../FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll

all: libfpcbep.a difftest

libfpcbep.a: $(OBJ)
	$(AR) rcs $@ $^

%.o: %.c include/fpc_bep.h
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

difftest: tools/difftest.c libfpcbep.a $(NATIVE)/pe_loader.c $(NATIVE)/win32_shims.c
	$(CC) $(CFLAGS) $(INCS) -o $@ tools/difftest.c $(NATIVE)/pe_loader.c \
	      $(NATIVE)/win32_shims.c libfpcbep.a $(LDFLAGS)

check: difftest
	./difftest "$(DLL)"

clean:
	rm -f $(OBJ) libfpcbep.a difftest

.PHONY: all check clean
