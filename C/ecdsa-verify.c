#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

#include "reader.h"
#include "writer.h"

static int verify_signature_for_file(const char *filename);
int create_hash(const char* filename, unsigned char *hash, size_t *len);

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "syntax error: %s <filename that contains signature>",
            argv[0]);
    return 1;
  }

  return verify_signature_for_file(argv[1]);
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
    assert(ch != EOF);
  }

  mbedtls_mpi r, s, x, y, z;
  fread_mbedtls_mpi(f, &r);
  fread_mbedtls_mpi(f, &s);
  fread_mbedtls_mpi(f, &x);
  fread_mbedtls_mpi(f, &y);
  fread_mbedtls_mpi(f, &z);
  fclose(f);

  unsigned char hash[MBEDTLS_MD_MAX_SIZE];
  size_t len;
  int rc = create_hash(target_filename, hash, &len);
  assert(rc == 0);

  const mbedtls_ecp_curve_info *curve_info = NULL;
  for (curve_info = mbedtls_ecp_curve_list();
          curve_info->grp_id != MBEDTLS_ECP_DP_BP512R1; curve_info++)
      ;
  assert(curve_info->grp_id == MBEDTLS_ECP_DP_BP512R1);
#ifdef DEBUG
  fprintf(stderr, "DEBUG:bit size %d, ECDSA-%s \n", curve_info->bit_size,
          curve_info->name);
#endif

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  rc = mbedtls_ecp_group_load(&grp, curve_info->grp_id);
  assert(rc == 0);
  mbedtls_ecp_point Q = {X:x, Y:y, Z:z} ;
  rc = mbedtls_ecdsa_verify(&grp, hash, len, &Q, &r, &s);
  switch(rc) {
  case 0:
    printf("Signature is valid!\n");
    break;
  case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
    printf("Signature is invalid!\n");
    break;
  default:
    printf("error while verification\n");
    exit(1);
    break;
  }

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&x);
  mbedtls_mpi_free(&y);
  mbedtls_mpi_free(&z);

  return rc;
}

