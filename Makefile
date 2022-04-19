COMMON_CFLAGS := -fPIC -Ilibseccomp/include

all: libsandbox.so sandboxing.a

%.o: %.c
	$(CC) -c $(COMMON_CFLAGS) -o $@ $<

libsandbox.so: sandbox.o preload.o
	$(CC) -shared -Wl,--version-script=libsandbox.version -o $@ $^ libseccomp/src/.libs/libseccomp.a

sandboxing.a: sandboxing.o sandbox.o
	$(CC) -o $@ $^ libseccomp/src/.libs/libseccomp.a
