#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

static int verify_signature_for_file(const char *filename);
static void fread_mbedtls_mpi(FILE *f, mbedtls_mpi *mpi);

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "syntax error: %s <filename that contains signature>",
            argv[0]);
    return 1;
  }

  int ret = verify_signature_for_file(argv[1]);
  assert(ret == 0);
  return 0;
}

static int verify_signature_for_file(const char *filename) {
  char target_filename[PATH_MAX];
  FILE *f = fopen(filename, "rb");
  assert(f);
  {
    int ch;
    int i = 0;
    for (;;) {
      ch = fgetc(f);
      if (ch == EOF || ch == '\0') {
        break;
      }
      target_filename[i++] = ch;
    }
    target_filename[i] = '\0';
  }
  printf("File to be verified is named %s\n", target_filename);

  mbedtls_mpi r, s, x, y, z;
  fread_mbedtls_mpi(f, &r);
  fread_mbedtls_mpi(f, &s);
  fread_mbedtls_mpi(f, &x);
  fread_mbedtls_mpi(f, &y);
  fread_mbedtls_mpi(f, &z);
  fclose(f);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&x);
  mbedtls_mpi_free(&y);
  mbedtls_mpi_free(&z);

  return 0;
}

static void fread_mbedtls_mpi(FILE *f, mbedtls_mpi *mpi) {
  mbedtls_mpi_init(mpi);
}
