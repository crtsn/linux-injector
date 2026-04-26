CFLAGS+=-std=c99 -D_GNU_SOURCE -g -O0
DEPS = Makefile

all: injector dummy print64.bin

%.o: %.c %.h $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

injector: main.o clone64.bin mmap64.bin
	$(CC) $(CFLAGS) -o injector main.o $(LDFLAGS)

dummy: dummy.o
	$(CC) $(CFLAGS) -o dummy $^ $(LDFLAGS)

%.bin: %.asm $(DEPS)
	fasm $<

clean:
	rm -f injector dummy *.o *.bin

.PHONY: all clean debug
