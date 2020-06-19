#include <mbedtls/bignum.h>

void print_mbedtls_mpi(const char *mpiname, mbedtls_mpi mpi) {
  printf("%s (%ld bytes)\n", mpiname, sizeof(mpi));
  printf("%s.s: %d (%ld bytes)\n", mpiname, mpi.s, sizeof(mpi.s));
  printf("%s.n: %ld (%ld bytes)\n", mpiname, mpi.n, sizeof(mpi.n));
  printf("*%s.p: : ", mpiname);
  for (int i = 0; i < mpi.n; ++i) {
    mbedtls_mpi_uint limb = mpi.p[i];
    for (int j = 0; j < sizeof(limb); ++j)
      printf("%02x", ((unsigned char *)&limb)[j]);
  }
  printf(" (%ld bytes)\n", sizeof(*mpi.p) * mpi.n);
  printf("\n");
}

