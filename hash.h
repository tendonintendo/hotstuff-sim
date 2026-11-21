#ifndef HASH_H
#define HASH_H

#include <sodium.h>
#include <stdint.h>
#include <stddef.h>

#define HASH_LEN crypto_hash_sha256_BYTES

static inline void hash_bytes(uint8_t out[HASH_LEN], const uint8_t *in, size_t len) {
    crypto_hash_sha256(out, in, len);
}

#endif
