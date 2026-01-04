CC = gcc
CFLAGS = -std=c11 -O3 -Wall -Wextra -D_GNU_SOURCE
LDFLAGS = -static
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

all: ghostshm

ghostshm: src/ghostshm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test: ghostshm
	$(CC) -o tests/helpers/sysv_attach tests/helpers/sysv_attach.c
	$(CC) -o tests/helpers/create_shm_key tests/helpers/create_shm_key.c
	$(CC) -o tests/helpers/posix_map_hold tests/helpers/posix_map_hold.c
	$(CC) -o tests/helpers/posix_open_many tests/helpers/posix_open_many.c
	bash tests/integration_test.sh

install: ghostshm
	install -d $(BINDIR)
	install -m 0755 ghostshm $(BINDIR)/ghostshm

uninstall:
	rm -f $(BINDIR)/ghostshm

clean:
	rm -f ghostshm tests/helpers/sysv_attach tests/helpers/create_shm_key

.PHONY: all clean test install uninstall
