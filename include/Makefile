includedir ?= $(PREFIX)/include

HEADERS = accord.h accord_proto.h

.PHONY:all
all:

.PHONY:install
install: $(HEADERS)
	install -d -m 755 $(DESTDIR)$(includedir)
	install -m 644 $(HEADERS) $(DESTDIR)$(includedir)
