#include <assert.h>
#include <stdio.h>
#include "printer.h"

void print_mbedtls_mpi(const char *mpiname, const mbedtls_mpi *mpi) {
  printf("%s (%ld bytes)\n", mpiname, sizeof(*mpi));
  printf("%s.s: %d (%ld bytes)\n", mpiname, mpi->s, sizeof(mpi->s));
  printf("%s.n: %ld (%ld bytes)\n", mpiname, mpi->n, sizeof(mpi->n));
  printf("*%s.p: : ", mpiname);
  for (int i = 0; i < mpi->n; ++i) {
    mbedtls_mpi_uint limb = mpi->p[i];
    for (int j = 0; j < sizeof(limb); ++j)
      printf("%02x", ((unsigned char *)&limb)[j]);
  }
  printf(" (%ld bytes)\n", sizeof(*mpi->p) * mpi->n);
  printf("\n");
}

void fprint_mbedtls_mpi(FILE *f, const mbedtls_mpi *mpi) {
  size_t written;
  written = fwrite(&mpi->s, sizeof(mpi->s), 1, f);
  assert(written == 1);
  written = fwrite(&mpi->n, sizeof(mpi->n), 1, f);
  assert(written == 1);
  written = fwrite(mpi->p, sizeof(mbedtls_mpi_uint), mpi->n, f);
  assert(written == mpi->n);
}

