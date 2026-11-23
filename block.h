// block struct

#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <sodium.h>
#include "hash.h"
#include "tx.h"
#include "encode.h"

#define BLOCK_HEADER_LEN 80

typedef struct {
    uint64_t index;
    uint64_t timestamp;
    uint8_t hash[HASH_LEN];
    uint8_t prev_hash[HASH_LEN];
    uint8_t tx_root[HASH_LEN];
} Block;

typedef enum {
    BLOCK_OK = 0,
    BLOCK_ERR_TOO_MANY_TXS,
    BLOCK_ERR_FULL,
    BLOCK_ERR_TRUNCATED
} BlockResult;

const char *block_result_str(BlockResult result);

void compute_hash(const Block *block, uint8_t* output);
Block create_genesis_block(void);
BlockResult make_block(const Block *prev, const Tx txs[MAX_TXS], const size_t cnt, const uint64_t timestamp, Block *out);
void print_block(const Block *block);

BlockResult block_encode(Buf *out, const Block *b);
BlockResult block_decode(Block *out, Reader *r);
#endif