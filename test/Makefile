CFLAGS += -g -O3 -Wall -Wstrict-prototypes -I../include
CFLAGS += -D_GNU_SOURCE
CFLAGS += $(shell pkg-config --cflags glib-2.0)
LIBS += -lpthread

TESTS = test-io test-aio test-txn test-watch test-concurrent test-coroutine
TEST_XML_FILE = test-report.xml
TEST_HTML_FILE = test-report.html
TEST_LIBS += $(shell pkg-config --libs glib-2.0)

PROGRAMS = acrdbench watch_nodes watch_files
BDRBENCH_OBJS = acrdbench.o
BDRBENCH_DEP = $(BDRBENCH_OBJS:.o=.d)
WATCH_NODES_OBJS = watch_nodes.o
WATCH_NODES_DEP = $(TEST_OBJS:.o=.d)
WATCH_FILES_OBJS = watch_files.o
WATCH_FILES_DEP = $(TEST_OBJS:.o=.d)

TEST_IO_OBJS = test-io.o
TEST_IO_DEP = $(TEST_IO_OBJS:.o=.d)
TEST_AIO_OBJS = test-aio.o
TEST_AIO_DEP = $(TEST_TXN_OBJS:.o=.d)
TEST_TXN_OBJS = test-txn.o
TEST_TXN_DEP = $(TEST_TXN_OBJS:.o=.d)
TEST_WATCH_OBJS = test-watch.o
TEST_WATCH_DEP = $(TEST_WATCH_OBJS:.o=.d)
TEST_CONCURRENT_OBJS = test-concurrent.o
TEST_CONCURRENT_DEP = $(TEST_CONCURRENT_OBJS:.o=.d)
TEST_COROUTINE_OBJS = test-coroutine.o ../lib/coroutine.o
TEST_COROUTINE_DEP = $(TEST_COROUTINE_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

acrdbench: $(BDRBENCH_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS)

watch_nodes: $(WATCH_NODES_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS)

watch_files: $(WATCH_FILES_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS)

test-io: $(TEST_IO_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS) $(TEST_LIBS)

test-aio: $(TEST_AIO_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS) $(TEST_LIBS)

test-txn: $(TEST_TXN_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS) $(TEST_LIBS)

test-watch: $(TEST_WATCH_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS) $(TEST_LIBS)

test-concurrent: $(TEST_CONCURRENT_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS) $(TEST_LIBS)

test-coroutine: $(TEST_COROUTINE_OBJS) ../libacrd/libacrd.a
	$(CC) $^ -o $@ $(LIBS) $(TEST_LIBS)

-include $(TEST_DEP)
-include $(BDRBENCH_DEP)
-include $(WATCH_NODES_DEP)
-include $(WATCH_FILES_DEP)
-include $(TEST_IO_DEP)
-include $(TEST_AIO_DEP)
-include $(TEST_TXN_DEP)
-include $(TEST_WATCH_DEP)
-include $(TEST_CONCURRENT_DEP)
-include $(TEST_COROUTINE_DEP)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY:clean
clean:
	rm -f *.[od] $(PROGRAMS) $(TEST_XML_FILE)

.PHONY:test
test: $(TESTS)

.PHONY:check
check:
	gtester -k -o $(TEST_XML_FILE) $(TESTS); \
		gtester-report $(TEST_XML_FILE) > $(TEST_HTML_FILE)

# support for GNU Flymake
check-syntax:
	$(CC) $(CFLAGS) -fsyntax-only $(CHK_SOURCES)
