#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

#include "printer.h"

static int myrand( void *rng_state, unsigned char *output, size_t len);
static int create_keypair( mbedtls_ecp_group_id *grp_id, uint16_t *bit_size, mbedtls_mpi *d, mbedtls_ecp_point *Q);
static int export_keypair( mbedtls_ecp_group_id *grp_id, uint16_t *bit_size, mbedtls_mpi *d, mbedtls_ecp_point *Q);

int main(void) {
  const int ok = 0;
  mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
  uint16_t bit_size = 0;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;

  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  int rc = create_keypair(&grp_id, &bit_size, &d, &Q);
  if (rc != ok) {
    fprintf(stderr, "error: creation of ECDSA key pair failed\n");
    return 1;
  }

  rc = export_keypair(&grp_id, &bit_size, &d, &Q);
  if (rc != ok) {
    fprintf(stderr, "error: export of ECDSA key pair failed\n");
    return 1;
  }
  return 0;
}

static int create_keypair(
    mbedtls_ecp_group_id *grp_id,
    uint16_t *bit_size,
    mbedtls_mpi *d,
    mbedtls_ecp_point *Q) {
  const mbedtls_ecp_curve_info *curve_info = NULL;
  for (curve_info = mbedtls_ecp_curve_list();
       curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
       curve_info++)
      if (curve_info->grp_id == MBEDTLS_ECP_DP_BP512R1)
          break;
  if (curve_info->grp_id != MBEDTLS_ECP_DP_BP512R1)
      return -1;
  *grp_id = curve_info->grp_id;
  *bit_size = curve_info->bit_size;

  mbedtls_ecdsa_context ecdsa;
  memset(&ecdsa, 0, sizeof(ecdsa));
  mbedtls_ecdsa_init(&ecdsa);
  if (mbedtls_ecdsa_genkey(&ecdsa, *grp_id, myrand, NULL) != 0) {
      fprintf(stderr, "error: mbedtls_ecdsa_genkey() failed\n");
      return -1;
  }

  *d = ecdsa.d;
  *Q = ecdsa.Q;
#ifdef DEBUG
  printf("private key d:\n");
  print_mbedtls_mpi("d", d);
  printf("public key Q=(x,y,z):\n");
  print_mbedtls_mpi("x", &Q->X);
  print_mbedtls_mpi("y", &Q->Y);
  print_mbedtls_mpi("z", &Q->Z);
#endif

  return 0;
}

static int export_keypair(
    mbedtls_ecp_group_id *grp_id,
    uint16_t *bit_size,
    mbedtls_mpi *d,
    mbedtls_ecp_point *Q) {
  // create file private key
  const char private_key_file[] = "key.priv";
  FILE *f = fopen(private_key_file, "wb");
  if (!f) { return -1; }
  fwrite(grp_id, sizeof(*grp_id), 1, f);
  fwrite(bit_size, sizeof(*bit_size), 1, f);
  fprint_mbedtls_mpi(f, d);
  fclose(f);

  const char public_key_file[] = "key.pub";
  f = fopen(public_key_file, "wb");
  if (!f) { return -1; }
  fwrite(grp_id, sizeof(*grp_id), 1, f);
  fwrite(bit_size, sizeof(*bit_size), 1, f);
  fprint_mbedtls_mpi(f, &Q->X);
  fprint_mbedtls_mpi(f, &Q->Y);
  fprint_mbedtls_mpi(f, &Q->Z);
  fclose(f);

  return 0;
}

static int myrand(void *rng_state, unsigned char *output, size_t len) {
  fprintf(stderr, "myrand() called with rng_state=%p and len=%ld \n", rng_state,
          len);

  if (rng_state != NULL)
    rng_state = NULL;

  FILE *fp = fopen("/dev/urandom", "rb");
  assert(fp);
  for (;;) {
    size_t read = fread(output, sizeof *output, len, fp);
    len -= read;
    if (len == 0) {
      break;
    }
  }

  return 0;
}
