#pragma once
#include <mbedtls/bignum.h>
void fread_mbedtls_mpi(FILE *f, mbedtls_mpi *mpi);
