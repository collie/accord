VERSION ?= 0.0.1

PREFIX ?= /usr

export VERSION PREFIX

.PHONY:all
all:
	$(MAKE) -C libacrd
	$(MAKE) -C conductor
	$(MAKE) -C test

.PHONY:clean
clean:
	$(MAKE) -C libacrd clean
	$(MAKE) -C conductor clean
	$(MAKE) -C test clean
	$(MAKE) -C lib clean

.PHONY:install
install:
	$(MAKE) -C libacrd install
	$(MAKE) -C conductor install
	$(MAKE) -C include install

.PHONY:test
test:
	$(MAKE) -C libacrd
	$(MAKE) -C test test

.PHONY:check
check: test
	$(MAKE) -C test check
