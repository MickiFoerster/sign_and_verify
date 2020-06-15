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

int mbedtls_ecdsa_write_my_signature(const unsigned char *hash,
                                     unsigned char *sig, size_t *slen) {
  static mbedtls_ecdsa_context ecdsa;
  static const mbedtls_ecp_curve_info *curve_info = NULL;

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

  printf("r=");
  for (int i = 0; i < sizeof(struct mbedtls_mpi); ++i)
    printf("%02x", ((unsigned char *)&r)[i]);
  printf("\ns=");
  for (int i = 0; i < sizeof(struct mbedtls_mpi); ++i)
    printf("%02x", ((unsigned char *)&s)[i]);
  printf("\n");

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  return (ret);
}

int main(void)
{
  unsigned char buffer[1024];
  unsigned char ec_result[1024];
  int ret;
  size_t sig_len;

  memset(buffer, 0x2a, sizeof(buffer));
  ret = mbedtls_ecdsa_write_my_signature(buffer, ec_result, &sig_len);
  assert(ret == 0);
  return 0;
}
