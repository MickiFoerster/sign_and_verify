#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>

int create_hash(const char* filename, unsigned char *hash, size_t *len) {
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

  int rc = mbedtls_md_file(md_info, filename, hash);
  assert(rc == 0);
  *len = mbedtls_md_get_size(md_info);

#ifdef DEBUG
  fprintf(stderr, "%s: ", filename);
  for (int i = 0; i < mbedtls_md_get_size(md_info); ++i) {
    fprintf(stderr, "%02x", hash[i]);
  }
  fprintf(stderr, "\n");
#endif 

  return rc;
}
