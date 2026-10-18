CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=c99
LDLIBS  ?= -lm

all: fpc_match_tool

fpc_match.o: fpc_match.c fpc_match.h
	$(CC) $(CFLAGS) -c -o $@ fpc_match.c

fpc_match_tool: fpc_match_tool.c fpc_match.o fpc_match.h
	$(CC) $(CFLAGS) -o $@ fpc_match_tool.c fpc_match.o $(LDLIBS)

clean:
	rm -f fpc_match.o fpc_match_tool

.PHONY: all clean
