CFLAGS += -g -O3 -Wall -Wstrict-prototypes -I../include
CFLAGS += -D_GNU_SOURCE -DNDEBUG -fPIC

LIBRARIES = libacrd.a libacrd.so
LIBACRD_OBJS = libacrd.o ../lib/net.o ../lib/work.o ../lib/coroutine.o
LIBACRD_DEP = $(LIBACRD_OBJS:.o=.d)
LIBACRD_VERSION = libacrd.map

ARFLAGS = cru
RANLIB = ranlib

.PHONY:all
all: $(LIBRARIES)

libacrd.a: $(LIBACRD_OBJS)
	$(AR) $(ARFLAGS) $@ $^
	$(RANLIB) $@

libacrd.so: $(LIBACRD_OBJS)
	$(CC) -shared $^ -o $@ -Wl,-version-script=$(LIBACRD_VERSION)

-include $(LIBACRD_DEP)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY:clean
clean:
	echo $(ARFLAGS)
	echo $(RANLIB)
	rm -f *.[od] $(LIBRARIES)

# support for GNU Flymake
check-syntax:
	$(CC) $(CFLAGS) -fsyntax-only $(CHK_SOURCES)
