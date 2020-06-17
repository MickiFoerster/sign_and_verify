#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

void print_mbedtls_mpi(const char *mpiname, mbedtls_mpi mpi);
static int myrand(void *rng_state, unsigned char *output, size_t len);
static int create_signature_for_file(const char *filename);
static void fprint_mbedtls_mpi(FILE *f, mbedtls_mpi mpi);
int create_hash(const char* filename, unsigned char *hash, size_t *len);

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

  mbedtls_ecdsa_context ecdsa;
  const mbedtls_ecp_curve_info *curve_info = NULL;

  int ret;
  mbedtls_mpi r, s;
  printf("sizeof(mbedtls_mpi_uint): %lu\n", sizeof(mbedtls_mpi_uint));
  printf("sizeof(mbedtls_t_udbl): %lu\n", sizeof(mbedtls_t_udbl));

  if (curve_info == NULL) {
    for (curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_BP512R1; curve_info++)
      ;
    assert(curve_info->grp_id == MBEDTLS_ECP_DP_BP512R1);
#ifdef DEBUG
    fprintf(stderr, "DEBUG:bit size %d, ECDSA-%s \n", curve_info->bit_size,
            curve_info->name);
#endif
    if (curve_info->grp_id != MBEDTLS_ECP_DP_BP512R1)
      return -1;
    memset(&ecdsa, 0, sizeof(ecdsa));
    mbedtls_ecdsa_init(&ecdsa);
    if ((ret = mbedtls_ecdsa_genkey(&ecdsa, curve_info->grp_id, myrand,
                                    NULL)) != 0) {
      fprintf(stderr, "error: mbedtls_ecdsa_genkey() returned %d\n", ret);
      return -1;
    }
  }
  assert(curve_info != NULL);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  ret = mbedtls_ecdsa_sign_det(&ecdsa.grp, &r, &s, &ecdsa.d, hash,
                               curve_info->bit_size, MBEDTLS_MD_SHA512);
  if (ret == 0)
    printf("Succesful signature\n");
  assert(ret == 0);

  // optional output for user
  print_mbedtls_mpi("r", r);
  printf("\n");
  print_mbedtls_mpi("s", s);
  printf("\n");

  printf("public key Q=(x,y,z):\n");
  print_mbedtls_mpi("x", ecdsa.Q.X);
  printf("\n");
  print_mbedtls_mpi("y", ecdsa.Q.Y);
  printf("\n");
  print_mbedtls_mpi("z", ecdsa.Q.Z);
  printf("\n");

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
  fprint_mbedtls_mpi(f, r);
  fprint_mbedtls_mpi(f, s);
  fprint_mbedtls_mpi(f, ecdsa.Q.X);
  fprint_mbedtls_mpi(f, ecdsa.Q.Y);
  fprint_mbedtls_mpi(f, ecdsa.Q.Z);
  fclose(f);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  return (ret);
}

static void fprint_mbedtls_mpi(FILE *f, mbedtls_mpi mpi) {
  size_t written;
  written = fwrite(&mpi.s, sizeof(mpi.s), 1, f);
  assert(written == 1);
  written = fwrite(&mpi.n, sizeof(mpi.n), 1, f);
  assert(written == 1);
  written = fwrite(mpi.p, sizeof(mbedtls_mpi_uint), mpi.n, f);
  assert(written == mpi.n);
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
