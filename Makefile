CC = gcc
CFLAGS = -std=c11 -O3 -Wall -Wextra -D_GNU_SOURCE
LDFLAGS = -static

all: ghostshm

ghostshm: src/ghostshm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test: ghostshm
	$(CC) -o tests/helpers/sysv_attach tests/helpers/sysv_attach.c
	$(CC) -o tests/helpers/create_shm_key tests/helpers/create_shm_key.c
	bash tests/integration_test.sh

clean:
	rm -f ghostshm tests/helpers/sysv_attach tests/helpers/create_shm_key

.PHONY: all clean test
