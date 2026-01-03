#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void handle_sigterm(int sig) {
    (void)sig;
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <shmid>\n", argv[0]);
        return 1;
    }

    int shmid = atoi(argv[1]);
    void *addr = shmat(shmid, NULL, 0);
    if (addr == (void *)-1) {
        perror("shmat");
        return 1;
    }

    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    printf("Attached to shmid %d. Sleeping...\n", shmid);
    fflush(stdout);

    while (1) {
        sleep(10);
    }

    shmdt(addr);
    return 0;
}
