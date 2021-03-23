#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>

const char testfile[] = "testfile";
unsigned char hashes[32][MBEDTLS_MD_MAX_SIZE];
int current_hash_sum = 0;

#define TEST_PREV                                                              \
    const mbedtls_md_info_t *md_info =                                         \
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);                          \
    if (md_info == NULL) {                                                     \
      fprintf(stderr, "error: mbedtls_md_info_from_type failed\n");            \
      exit(1);                                                                 \
    }                                                                          \
                                                                               \
    mbedtls_md_context_t md_ctx;                                               \
    mbedtls_md_init(&md_ctx);                                                  \
    if (mbedtls_md_setup(&md_ctx, md_info, 0 /* don't use HMAC */) != 0) {     \
      fprintf(stderr, "error: mbedtls_md_setup failed\n");                     \
      exit(1);                                                                 \
    }                                                                          \
                                                                               \
    struct timeval start, end;                                                 \
    gettimeofday(&start, NULL);

#define TEST_AFTER(TEST_NAME)                                                  \
  gettimeofday(&end, NULL);                                                    \
  print_result(TEST_NAME, md_info, &start, &end);                              \
  mbedtls_md_free(&md_ctx);

void print_result(const char *testname, const mbedtls_md_info_t *md_info,
                  struct timeval *start, struct timeval *end) {
  long seconds = end->tv_sec - start->tv_sec;
  long micros = 0;
  if (end->tv_usec >= start->tv_usec) {
    micros = end->tv_usec - start->tv_usec;
  } else {
    seconds--;
    micros = 1000000 + end->tv_usec - start->tv_usec;
  }
  fprintf(stderr, "%-32s took %03lds:%03ldms:        ", testname, seconds,
          micros / 1000);
  for (int i = 0; i < mbedtls_md_get_size(md_info); ++i) {
    fprintf(stderr, "%02x", hashes[current_hash_sum][i]);
  }
  fprintf(stderr, "\n");
}

void hash_whole_file_by_providing_path(void) {
  TEST_PREV;
  int rc = mbedtls_md_file(md_info, testfile, hashes[current_hash_sum]);
  assert(rc == 0);
  TEST_AFTER("mbedtls_md_file");
}

void hash_whole_file_with_sequence_of_updates(const int buffersize) {
  TEST_PREV;
  int fd = open(testfile, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "error: could not open file %s\n", testfile);
    exit(1);
  }

  int rc = mbedtls_md_starts(&md_ctx);
  assert(rc == 0);
  for (;;) {
    unsigned char buf[buffersize];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n > 0) {
      rc = mbedtls_md_update(&md_ctx, buf, n);
      assert(rc == 0);
    } else if (n < 0) {
      fprintf(stderr, "error while reading file %s\n", testfile);
      exit(1);
    } else {
      break; // EOF
    }
  }
  rc = mbedtls_md_finish(&md_ctx, hashes[current_hash_sum]);
  assert(rc == 0);
  close(fd);

  char msg[128];
  snprintf(msg, sizeof msg, "seq of updates %8dkb", buffersize / 1024);
  TEST_AFTER(msg);
}

void hash_whole_file_with_2_threads() {
  TEST_PREV;

  struct stat st;
  int rc = stat(testfile, &st);
  assert(rc == 0);
  assert(st.st_size % 2 == 0);
  rc = mbedtls_md_starts(&md_ctx);
  assert(rc == 0);
  int num_threads = 0;
#pragma omp parallel num_threads(2)
  {
#pragma omp master
    num_threads = omp_get_num_threads();
#pragma omp sections
    {
#pragma omp section
    {
      int fd = open(testfile, O_RDONLY);
      if (fd < 0) {
        fprintf(stderr, "error: could not open file %s\n", testfile);
        exit(1);
      }
      int rc = lseek(fd, 0, SEEK_SET);
      if (rc < 0) {
        fprintf(stderr, "error: lseek failed: %s\n", strerror(errno));
        exit(1);
      }
      const int sz = st.st_size / 2;
      unsigned char buf[1024];
      for (int i = 0; i < sz; i += sizeof buf) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n > 0) {
#pragma omp critical
          { rc = mbedtls_md_update(&md_ctx, buf, n); }
          assert(rc == 0);
        } else if (n < 0) {
          fprintf(stderr, "error while reading file %s: %s\n", testfile,
                  strerror(errno));
          exit(1);
        }
      }
      close(fd);
    }
#pragma omp section
    {
      int fd = open(testfile, O_RDONLY);
      if (fd < 0) {
        fprintf(stderr, "error: could not open file %s\n", testfile);
        exit(1);
      }
      const int sz = st.st_size / 2;
      int rc = lseek(fd, sz, SEEK_SET);
      if (rc < 0) {
        fprintf(stderr, "error: lseek failed: %s\n", strerror(errno));
        exit(1);
      }
      unsigned char buf[1024];
      for (int i = 0; i < sz; i += sizeof buf) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n > 0) {
#pragma omp critical
          { rc = mbedtls_md_update(&md_ctx, buf, n); }
          assert(rc == 0);
        } else if (n < 0) {
          fprintf(stderr, "error while reading file %s: %s\n", testfile,
                  strerror(errno));
          exit(1);
        }
      }
      close(fd);
    }
    }
  }

  rc = mbedtls_md_finish(&md_ctx, hashes[current_hash_sum]);
  assert(rc == 0);

  char msg[128];
  snprintf(msg, sizeof msg, "with %d threads", num_threads);
  TEST_AFTER(msg);
}

int main() {
  hash_whole_file_by_providing_path();
  current_hash_sum++;

  hash_whole_file_with_sequence_of_updates(1024);
  current_hash_sum++;
  hash_whole_file_with_sequence_of_updates(4 * 1024);
  current_hash_sum++;
  hash_whole_file_with_sequence_of_updates(8 * 1024);
  current_hash_sum++;
  hash_whole_file_with_sequence_of_updates(32 * 1024);
  current_hash_sum++;
  hash_whole_file_with_sequence_of_updates(256 * 1024);
  current_hash_sum++;
  hash_whole_file_with_sequence_of_updates(1024 * 1024);
  current_hash_sum++;

  //hash_whole_file_with_2_threads();
  //current_hash_sum++;

  return 0;
}

