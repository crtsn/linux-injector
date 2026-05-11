CFLAGS+=-std=c99 -D_GNU_SOURCE -g -O0 -z execstack -fno-stack-protector 

all: injector dummy

injector: main.c Makefile
	$(CC) $(CFLAGS) -fPIC -shared \
		-Wl,-e,_start \
		-o injector main.c $(LDFLAGS)
	file injector
	readelf -l injector | grep INTERP -A 1 || true

dummy: dummy.c Makefile
	$(CC) $(CFLAGS) -o dummy $< $(LDFLAGS)

clean:
	rm -f injector dummy

.PHONY: all clean debug
