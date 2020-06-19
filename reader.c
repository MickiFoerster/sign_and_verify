#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "reader.h"

void fread_mbedtls_mpi(FILE *f, mbedtls_mpi *mpi) {
  mbedtls_mpi_init(mpi);

  size_t read;
  read = fread(&mpi->s, sizeof(mpi->s), 1, f);
  assert(read==1);
  read = fread(&mpi->n, sizeof(mpi->n), 1, f);
  assert(read==1);

  mpi->p = malloc(sizeof(mbedtls_mpi_uint)*mpi->n);
  assert(mpi->p);
  memset(mpi->p, 0, sizeof(mbedtls_mpi_uint)*mpi->n);
  read = fread(mpi->p, sizeof(mbedtls_mpi_uint), mpi->n, f);
  assert(read == mpi->n);
}
