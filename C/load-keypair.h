#pragma once

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

int import_keypair(mbedtls_ecp_group_id *grp_id, uint16_t *bit_size,
                   mbedtls_mpi *d, mbedtls_ecp_point *Q);
