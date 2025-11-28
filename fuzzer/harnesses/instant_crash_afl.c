// Auto-generated AFL++ harness for instant_crash
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

// Pull in the implementation (includes static functions)
#include "../../ossfuzz-target/src/vuln_lib.c"

#define MAX_INPUT (1 << 16)

int main(int argc, char **argv) {
  uint8_t buf[MAX_INPUT];
  ssize_t len = 0;

  if (argc > 1) {
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
      return 0;
    }
    len = (ssize_t)fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
  } else {
    len = read(STDIN_FILENO, buf, sizeof(buf));
  }

  if (len <= 0) {
    return 0;
  }

  instant_crash(buf, (size_t)len);
  return 0;
}
