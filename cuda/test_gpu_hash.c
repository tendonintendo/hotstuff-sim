#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>
#include "../block.h"
#include "../encode.h"
#include "../prng.h"
#include "gpu_hash.h"

_Static_assert(GPU_HEADER_LEN == BLOCK_HEADER_LEN, "GPU_HEADER_LEN must match BLOCK_HEADER_LEN");
_Static_assert(GPU_DIGEST_LEN == HASH_LEN, "GPU_DIGEST_LEN must match HASH_LEN");

#define HEADER_COUNT 1000000
#define MAX_RANDOM_LEN 200

static int checks = 0;
static int failures = 0;

#define CHECK(cond) do { \
    checks++; \
    if (!(cond)) { \
        failures++; \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

// now_seconds: monotonic wall-clock time in seconds
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// print_digest: print a 32-byte digest as hex
static void print_digest(const char *label, const uint8_t d[GPU_DIGEST_LEN]) {
    fprintf(stderr, "  %s ", label);
    for (int i = 0; i < GPU_DIGEST_LEN; i++) fprintf(stderr, "%02x", d[i]);
    fprintf(stderr, "\n");
}

// hex_to_bytes: decode a 64-char hex string into 32 bytes
static void hex_to_bytes(uint8_t out[GPU_DIGEST_LEN], const char *hex) {
    for (int i = 0; i < GPU_DIGEST_LEN; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

// check_vector: gpu_sha256 of msg must equal the expected FIPS digest
static void check_vector(const char *msg, const char *expected_hex) {
    uint8_t expected[GPU_DIGEST_LEN];
    uint8_t got[GPU_DIGEST_LEN] = {0};
    hex_to_bytes(expected, expected_hex);
    CHECK(gpu_sha256(got, (const uint8_t *)msg, strlen(msg)) == GPU_OK);
    int ok = memcmp(got, expected, GPU_DIGEST_LEN) == 0;
    CHECK(ok);
    if (!ok) {
        fprintf(stderr, "  vector \"%s\" (len %zu)\n", msg, strlen(msg));
        print_digest("expected", expected);
        print_digest("got     ", got);
    }
}

// test_fips_vectors: empty string, "abc", and the 56-byte two-block-padding case
static void test_fips_vectors(void) {
    check_vector("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_vector("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_vector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

// test_random_lengths: gpu_sha256 matches libsodium for random inputs of every length 0..MAX_RANDOM_LEN
static void test_random_lengths(void) {
    PRNG rng = prng_init(42);
    uint8_t msg[MAX_RANDOM_LEN];
    for (size_t len = 0; len <= MAX_RANDOM_LEN; len++) {
        for (size_t i = 0; i < len; i++) msg[i] = (uint8_t)prng_next(&rng);
        uint8_t expected[GPU_DIGEST_LEN];
        uint8_t got[GPU_DIGEST_LEN] = {0};
        crypto_hash_sha256(expected, msg, len);
        CHECK(gpu_sha256(got, msg, len) == GPU_OK);
        int ok = memcmp(got, expected, GPU_DIGEST_LEN) == 0;
        CHECK(ok);
        if (!ok) {
            fprintf(stderr, "  random input len %zu\n", len);
            print_digest("expected", expected);
            print_digest("got     ", got);
            return;
        }
    }
}

// test_zero_headers: n == 0 succeeds without touching the output
static void test_zero_headers(void) {
    uint8_t digest[GPU_DIGEST_LEN] = {0xAA};
    CHECK(gpu_hash_headers(digest, NULL, 0) == GPU_OK);
    CHECK(digest[0] == 0xAA);
}

// random_block: block i with random timestamp, prev_hash and tx_root
static Block random_block(PRNG *rng, uint64_t i) {
    Block b;
    memset(&b, 0, sizeof(b));
    b.index = i;
    b.timestamp = prng_next(rng);
    for (size_t j = 0; j < HASH_LEN; j++) {
        b.prev_hash[j] = (uint8_t)prng_next(rng);
        b.tx_root[j] = (uint8_t)prng_next(rng);
    }
    return b;
}

// test_million_headers: every GPU digest matches compute_hash on the CPU
static void test_million_headers(void) {
    uint8_t *headers = malloc((size_t)HEADER_COUNT * BLOCK_HEADER_LEN);
    uint8_t *expected = malloc((size_t)HEADER_COUNT * HASH_LEN);
    uint8_t *got = calloc((size_t)HEADER_COUNT, HASH_LEN);
    CHECK(headers != NULL && expected != NULL && got != NULL);
    if (headers == NULL || expected == NULL || got == NULL) goto done;

    PRNG rng = prng_init(7);
    double t0 = now_seconds();
    for (size_t i = 0; i < HEADER_COUNT; i++) {
        Block b = random_block(&rng, i);
        Buf buf = init_enc_buf(headers + i * BLOCK_HEADER_LEN, BLOCK_HEADER_LEN);
        CHECK(block_encode(&buf, &b) == BLOCK_OK);
        CHECK(buf.len == BLOCK_HEADER_LEN);
        compute_hash(&b, expected + i * HASH_LEN);
    }
    double t1 = now_seconds();
    CHECK(gpu_hash_headers(got, headers, HEADER_COUNT) == GPU_OK);
    double t2 = now_seconds();

    size_t mismatches = 0;
    for (size_t i = 0; i < HEADER_COUNT; i++) {
        if (memcmp(got + i * HASH_LEN, expected + i * HASH_LEN, HASH_LEN) != 0) {
            if (mismatches == 0) {
                fprintf(stderr, "  first mismatch at header %zu\n", i);
                print_digest("expected", expected + i * HASH_LEN);
                print_digest("got     ", got + i * HASH_LEN);
            }
            mismatches++;
        }
    }
    CHECK(mismatches == 0);

    printf("%d headers: %zu mismatches, cpu %.3f s (generate+encode+hash), gpu %.3f s (incl. transfers)\n",
           HEADER_COUNT, mismatches, t1 - t0, t2 - t1);

done:
    free(headers);
    free(expected);
    free(got);
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    test_fips_vectors();
    test_random_lengths();
    test_zero_headers();
    test_million_headers();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
