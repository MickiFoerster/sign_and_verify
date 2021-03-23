#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reader.h"
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

int import_keypair(mbedtls_ecp_group_id *grp_id, uint16_t *bit_size,
                   mbedtls_mpi *d, mbedtls_ecp_point *Q) {
  const char private_key_file[] = "key.priv";
  const char public_key_file[] = "key.pub";

  FILE *f = fopen(private_key_file, "rb");
  if (!f) { return -1; }

  fread(grp_id, sizeof(*grp_id), 1, f);
  fread(bit_size, sizeof(*bit_size), 1, f);
  fread_mbedtls_mpi(f, d);
  fclose(f);

  f = fopen(public_key_file, "rb");
  if (!f) { return -1; }
  fread(grp_id, sizeof(*grp_id), 1, f);
  fread(bit_size, sizeof(*bit_size), 1, f);
  fread_mbedtls_mpi(f, &Q->X);
  fread_mbedtls_mpi(f, &Q->Y);
  fread_mbedtls_mpi(f, &Q->Z);
  fclose(f);

  return 0;
}
