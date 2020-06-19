#include <assert.h>
#include <stdio.h>

int main() {
  FILE *fp = fopen("/dev/urandom", "rb");
  if (!fp) {
    return 1;
    }

    unsigned char buffer[1024];
    size_t read = fread(buffer, 1, sizeof buffer, fp);
    printf("read %ld bytes\n", read);
    assert(read == sizeof buffer);
    for (int i = 0; i < sizeof buffer; ++i) {
      printf("%02x", buffer[i]);
    }
}
