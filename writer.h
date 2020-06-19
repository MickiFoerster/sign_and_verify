#pragma once

#include <mbedtls/bignum.h>

void print_mbedtls_mpi(const char *mpiname, const mbedtls_mpi *mpi);
void fprint_mbedtls_mpi(FILE *f, const mbedtls_mpi *mpi);
