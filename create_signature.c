#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

static void print_mbedtls_mpi(const char *mpiname, mbedtls_mpi mpi);
static int myrand(void *rng_state, unsigned char *output, size_t len);
static int create_signature_for_file(const char *filename);
static void fprint_mbedtls_mpi(FILE *f, mbedtls_mpi mpi);

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
  const mbedtls_md_info_t *md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  if (md_info == NULL) {
    fprintf(stderr, "error: mbedtls_md_info_from_type failed\n");
    exit(1);
  }

  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);
  if (mbedtls_md_setup(&md_ctx, md_info, 0 /* don't use HMAC */) != 0) {
    fprintf(stderr, "error: mbedtls_md_setup failed\n");
    exit(1);
  }

  unsigned char hash[MBEDTLS_MD_MAX_SIZE];
  int rc = mbedtls_md_file(md_info, filename, hash);
  assert(rc == 0);
  fprintf(stderr, "%s: ", filename);
  for (int i = 0; i < mbedtls_md_get_size(md_info); ++i) {
    fprintf(stderr, "%02x", hash[i]);
  }
  fprintf(stderr, "\n");

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
    fprintf(stderr, "DEBUG:bit size %d, ECDSA-%s \n", curve_info->bit_size,
            curve_info->name);
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

static void print_mbedtls_mpi(const char *mpiname, mbedtls_mpi mpi) {
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

  FILE *fp = fopen("/dev/random", "rb");
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
