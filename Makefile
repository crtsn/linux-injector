CFLAGS+=-std=c99 -D_GNU_SOURCE -g -O0 -z execstack -fno-stack-protector 
DEPS = Makefile

all: injector dummy

%.o: %.c %.h $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

injector: main.o
	$(CC) $(CFLAGS) -o injector main.o $(LDFLAGS)

dummy: dummy.o
	$(CC) $(CFLAGS) -o dummy $^ $(LDFLAGS)

clean:
	rm -f injector dummy *.o

.PHONY: all clean debug
