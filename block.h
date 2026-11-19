// block struct

#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <openssl/sha.h>

typedef struct {
    long long index;
    time_t timestamp;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t prev_hash[SHA256_DIGEST_LENGTH];
} Block;

void compute_hash(const Block *block, uint8_t* output);
Block create_genesis_block(void);
Block append_block(const Block *block);

#endif