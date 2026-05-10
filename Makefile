CFLAGS+=-std=c99 -D_GNU_SOURCE -g -O0 -z execstack -fno-stack-protector 

all: injector dummy

injector: main.c Makefile
	$(CC) $(CFLAGS) -fPIC -o injector main.c $(LDFLAGS)

dummy: dummy.c Makefile
	$(CC) $(CFLAGS) -o dummy $< $(LDFLAGS)

clean:
	rm -f injector dummy *.o

.PHONY: all clean debug
