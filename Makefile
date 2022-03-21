CC = clang
CCC = clang++
LDFLAGS = -lnacl -lpthread -lrt
CFLAGS = -O2 -fno-strict-aliasing -Wall -Wextra -Wstrict-prototypes \
	 -Wmissing-prototypes -Wmissing-declarations -Werror=implicit \
	 -Wdeclaration-after-statement -D_GNU_SOURCE \
	 -Wno-address-of-packed-member
CCFLAGS = -O2 -std=c++17 -Wall -Wextra -D_GNU_SOURCE

all: sdvrc sdvrd tests runtests mods
mods: poc-ffplay
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

sdvrc: sdvrc.o v4l2.o inet.o crypto.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

sdvrd: sdvrd.o crypto.o inet.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

tests: tests.o crypto.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

poc-ffplay: poc-ffplay.o
	$(CCC) -o $@ $^ $(CCFLAGS) $(LDFLAGS)

runtests: tests
	./tests

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@

%.o: %.cpp
	$(CCC) $< $(CFLAGS) -c -o $@

%.s: %.c
	$(CC) $< $(CFLAGS) -c -S -o $@

clean:
	rm -f sdvrc sdvrd tests poc-ffplay
	rm -f *.o *.s
