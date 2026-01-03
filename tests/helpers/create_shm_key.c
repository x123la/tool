#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <key_hex>\n", argv[0]);
        return 1;
    }

    key_t key = (key_t)strtoul(argv[1], NULL, 0);
    int shmid = shmget(key, 1024, IPC_CREAT | 0600);
    if (shmid < 0) {
        if (errno == EEXIST) {
            shmid = shmget(key, 1024, 0);
        }
        if (shmid < 0) {
            perror("shmget");
            return 1;
        }
    }
    printf("%d\n", shmid);
    return 0;
}
