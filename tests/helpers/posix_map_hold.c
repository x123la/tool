#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <path> <size> <sleep_sec>\n", argv[0]);
    return 1;
  }

  const char *path = argv[1];
  size_t size = (size_t)strtoull(argv[2], NULL, 10);
  int sleep_sec = atoi(argv[3]);

  int fd = open(path, O_RDWR);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  if (ftruncate(fd, (off_t)size) != 0) {
    perror("ftruncate");
    close(fd);
    return 1;
  }

  void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED) {
    perror("mmap");
    close(fd);
    return 1;
  }

  close(fd);
  sleep(sleep_sec);
  munmap(addr, size);
  return 0;
}
