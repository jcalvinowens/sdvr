CC = gcc
CCC = g++
LDFLAGS = -lnacl -lpthread -lrt -z noexecstack
CFLAGS = -O2 -fno-strict-aliasing -Wall -Wextra -Wstrict-prototypes \
	 -Wmissing-prototypes -Wmissing-declarations -Werror=implicit \
	 -Wdeclaration-after-statement -D_GNU_SOURCE \
	 -Wno-address-of-packed-member
CCFLAGS = -O2 -std=c++17 -Wall -Wextra -D_GNU_SOURCE

all: sdvrc sdvrd tests runtests mods
mods: psdl prec
debug debug32: CCFLAGS += -g -Og -fsanitize=address -fsanitize=undefined
debug debug32: CFLAGS += -g -Og -fsanitize=address -fsanitize=undefined
debug: all
debug32: 32bit

32bit: CFLAGS += -m32
32bit: LDFLAGS += -m32
32bit: all

disasm: CFLAGS += -fverbose-asm
disasm: sdvrd.s sdvrc.s inet.s crypto.s v4l2.s
disasm: all

disasm32: 32bit
disasm32: disasm

psdl.o: output.h

sdvrc: sdvrc.o v4l2.o inet.o crypto.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

sdvrd: sdvrd.o crypto.o inet.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

tests: tests.o crypto.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

psdl: psdl.o
	$(CCC) -o $@ $^ $(CCFLAGS) $(LDFLAGS) -lSDL2 -lavcodec -lavutil

prec: prec.o
	$(CCC) -o $@ $^ $(CCFLAGS) $(LDFLAGS) -lavcodec -lavutil

runtests: tests
	./tests

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@

%.o: %.cpp
	$(CCC) $< $(CCFLAGS) -c -o $@

%.s: %.c
	$(CC) $< $(CFLAGS) -c -S -o $@

clean:
	rm -f sdvrc sdvrd tests psdl prec
	rm -f *.o *.s
