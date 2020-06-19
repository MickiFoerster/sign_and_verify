#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

#include "ecdsa-hash.h"
#include "load-keypair.h"
#include "writer.h"

static int create_signature_for_file(const char *filename);

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "syntax error: %s <filename that should be signed>",
            argv[0]);
    return 1;
  }

  int ret = create_signature_for_file(argv[1]);
  assert(ret == 0);
  return 0;
}

static int create_signature_for_file(const char *filename) {
  unsigned char hash[MBEDTLS_MD_MAX_SIZE];
  size_t len;
  int rc = create_hash(filename, hash, &len);
  assert(rc == 0);

  mbedtls_ecp_group_id grp_id;
  uint16_t bit_size;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  rc = import_keypair(&grp_id, &bit_size, &d, &Q);
  assert(rc == 0);

  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  rc = mbedtls_ecp_group_load(&grp, grp_id);
  assert(rc == 0);

  rc = mbedtls_ecdsa_sign_det(&grp, &r, &s, &d, hash, bit_size, MBEDTLS_MD_SHA512);
  if (rc == 0)
    printf("Succesful signature\n");
  assert(rc == 0);

  // optional output for user
  print_mbedtls_mpi("r", &r);
  print_mbedtls_mpi("s", &s);

  // create signature file
  char signature_filename[PATH_MAX];
  snprintf(signature_filename, sizeof(signature_filename), "%s.sig", filename);
  FILE *f = fopen(signature_filename, "wb");
  assert(f);
  {
    int ch;
    for (int i = 0; i < strlen(filename); ++i) {
      ch = fputc(filename[i], f);
      assert(ch == filename[i]);
    }
    ch = fputc('\0', f);
    assert(ch == '\0');
  }
  fprint_mbedtls_mpi(f, &r);
  fprint_mbedtls_mpi(f, &s);
  fprint_mbedtls_mpi(f, &Q.X);
  fprint_mbedtls_mpi(f, &Q.Y);
  fprint_mbedtls_mpi(f, &Q.Z);
  fclose(f);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);

  return rc;
}

