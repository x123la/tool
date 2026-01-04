#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <path> <count> <sleep_sec>\n", argv[0]);
    return 1;
  }

  const char *path = argv[1];
  int count = atoi(argv[2]);
  int sleep_sec = atoi(argv[3]);

  if (count <= 0) {
    fprintf(stderr, "count must be > 0\n");
    return 1;
  }

  int *fds = calloc((size_t)count, sizeof(int));
  if (!fds) {
    perror("calloc");
    return 1;
  }

  int opened = 0;
  for (int i = 0; i < count; i++) {
    fds[i] = open(path, O_RDONLY);
    if (fds[i] < 0) {
      perror("open");
      break;
    }
    opened++;
  }

  sleep(sleep_sec);

  for (int i = 0; i < opened; i++) {
    if (fds[i] >= 0)
      close(fds[i]);
  }
  free(fds);
  return 0;
}
