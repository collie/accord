sbindir ?= $(PREFIX)/sbin

CFLAGS += -g -O3 -Wall -Wstrict-prototypes -I../include
CFLAGS += -D_GNU_SOURCE -DNDEBUG
LIBS += -lpthread -ldb -lcpg

PROGRAMS = conductor
ACCORD_OBJS = store.o conductor.o acrdnet.o acrdops.o logger.o \
	../lib/event.o ../lib/net.o ../lib/work.o ../lib/coroutine.o
ACCORD_DEP = $(ACCORD_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

conductor: $(ACCORD_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include $(ACCORD_DEP)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY:clean
clean:
	rm -f *.[od] $(PROGRAMS)

.PHONY:install
install: $(PROGRAMS)
	install -d -m 755 $(DESTDIR)$(sbindir)
	install -m 755 $(PROGRAMS) $(DESTDIR)$(sbindir)

# support for GNU Flymake
check-syntax:
	$(CC) $(CFLAGS) -fsyntax-only $(CHK_SOURCES)
