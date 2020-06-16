#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <mbedtls/ecdsa.h>

static int myrand(void *rng_state, unsigned char *output, size_t len) {
#if 0
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
#else
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
#endif
}

#include <mbedtls/bignum.h>

int mbedtls_ecdsa_write_my_signature(const char *filename, unsigned char *sig,
                                     size_t *slen) {

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

  printf("r (%ld bytes)\n", sizeof(r));
  printf("r.s: %d (%ld bytes)\n", r.s, sizeof(r.s));
  printf("r.n: %ld (%ld bytes)\n", r.n, sizeof(r.n));
  printf("*r.p: : ");
  for (int i = 0; i < r.n; ++i) {
    mbedtls_mpi_uint limb = r.p[i];
    for (int j = 0; j < sizeof(limb); ++j)
      printf("%02x", ((unsigned char *)&limb)[j]);
  }
  printf(" (%ld bytes)\n", sizeof(mbedtls_mpi_uint) * r.n);

  printf("\n");
  printf("s (%ld bytes)\n", sizeof(s));
  printf("s.s: %d (%ld bytes)\n", s.s, sizeof(s.s));
  printf("s.n: %ld (%ld bytes)\n", s.n, sizeof(s.n));
  printf("*s.p: : ");
  for (int i = 0; i < s.n; ++i) {
    mbedtls_mpi_uint limb = s.p[i];
    for (int j = 0; j < sizeof(limb); ++j)
      printf("%02x", ((unsigned char *)&limb)[j]);
  }
  printf(" (%ld bytes)\n", sizeof(mbedtls_mpi_uint) * s.n);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

#if 0
outline above printing for easier usage for X,Y, and Z
  Q (public key output is missing)

typedef struct mbedtls_ecp_point
{
    mbedtls_mpi X;          /*!< The X coordinate of the ECP point. */
    mbedtls_mpi Y;          /*!< The Y coordinate of the ECP point. */
    mbedtls_mpi Z;          /*!< The Z coordinate of the ECP point. */
}
mbedtls_ecp_point;
#endif

  return (ret);
}

int main(int argc, char *argv[]) {
  unsigned char ec_result[1024];
  int ret;
  size_t sig_len;

  if (argc != 2) {
    fprintf(stderr, "syntax error: %s <filename that should be signed>",
            argv[0]);
    return 1;
  }

  ret = mbedtls_ecdsa_write_my_signature(argv[1], ec_result, &sig_len);
  assert(ret == 0);
  return 0;
}
