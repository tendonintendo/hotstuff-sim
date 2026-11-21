#ifndef MERKLE_H
#define MERKLE_H

#include <sodium.h>
#include "hash.h"
#include <stdint.h>
#include <stddef.h>

#define MERKLE_MAX_LEAVES 256
#define MERKLE_MAX_DEPTH 8

_Static_assert((1u << MERKLE_MAX_DEPTH) >= MERKLE_MAX_LEAVES,
               "MERKLE_MAX_DEPTH too small for MERKLE_MAX_LEAVES");

typedef struct{
    uint8_t siblings[MERKLE_MAX_DEPTH][HASH_LEN];
    size_t count;
    uint8_t sibling_is_left[MERKLE_MAX_DEPTH];
} MerkleProof;


typedef enum{
    MERKLE_OK = 0,
    MERKLE_ERR_ZERO_LEAVES,
    MERKLE_ERR_MAX_LEAVES_EXCEEDED,
    MERKLE_ERR_BAD_INDEX,
    MERKLE_ERR_MAX_DEPTH_EXCEEDED,
    MERKLE_ERR_INVALID_PROOF,
} MerkleResult;

MerkleResult merkle_root(const uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], uint8_t out[HASH_LEN], const size_t cnt);
MerkleResult merkle_proof(const uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], MerkleProof *proof, const size_t cnt, const size_t index);
MerkleResult merkle_verify(const uint8_t leaf[HASH_LEN], const MerkleProof *proof, const uint8_t root[HASH_LEN]);

#endif