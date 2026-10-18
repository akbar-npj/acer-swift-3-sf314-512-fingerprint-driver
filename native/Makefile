# Native (no-Wine) rehost of fpc_enclave.dll's BEP reconstruction.
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -I../cleanroom/include
LDLIBS  ?= -lpthread ../cleanroom/libfpcbep.a

TARGET  := fpc_recon_native
OBJS    := fpc_recon.o pe_loader.o win32_shims.o

all: $(TARGET)

$(TARGET): $(OBJS) ../cleanroom/libfpcbep.a
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c pe_loader.h win32_shims.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
