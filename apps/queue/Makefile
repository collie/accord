sbindir ?= $(PREFIX)/sbin

CFLAGS += -g -O3 -Wall -Wstrict-prototypes -I../../include
CFLAGS += -D_GNU_SOURCE -DNDEBUG
LIBS += -L../../libacrd -lpthread -lacrd

PROGRAMS = qbench
QUEUE_OBJS = queue.o
QUEUE_DEP = $(ACCORD_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

qbench: $(QUEUE_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

-include $(ACCORD_DEP)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY:clean
clean:
	rm -f *.[od] $(PROGRAMS)

# support for GNU Flymake
check-syntax:
	$(CC) $(CFLAGS) -fsyntax-only $(CHK_SOURCES)
