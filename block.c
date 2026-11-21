#include <stdio.h>
#include <string.h>
#include <time.h>
#include "helpers.h"
#include "block.h"
#include "merkle.h"
#include "tx.h"

_Static_assert(MAX_TXS <= MERKLE_MAX_LEAVES, "MAX_TXS must fit in one Merkle tree");

void compute_hash(const Block *block, uint8_t* output) {
    char payload[512];
    char prev_hash_hex[(HASH_LEN << 1) + 1];
    char tx_root_hex[(HASH_LEN << 1) + 1];
    to_hex(block->prev_hash, HASH_LEN, prev_hash_hex);
    to_hex(block->tx_root, HASH_LEN, tx_root_hex);
    snprintf(payload, sizeof(payload), "INDEX=%lld|TIMESTAMP=%lld|PREV_HASH=%s|TX_ROOT=%s", 
            block->index, (long long)block->timestamp, prev_hash_hex, tx_root_hex);

    hash_bytes(output, (unsigned char*)payload, strlen(payload));
}

Block create_genesis_block(void) {
    Block genesis = {0};
    genesis.timestamp = time(NULL);
    compute_hash(&genesis, genesis.hash);
    return genesis;
}

BlockResult make_block(const Block *prev, const Tx txs[MAX_TXS], const size_t cnt, Block *out) {
    if(cnt > MAX_TXS) return BLOCK_ERR_TOO_MANY_TXS;
    Block next = {0};
    next.timestamp = time(NULL) + prev->index + 1;
    next.index = prev->index + 1;
    memcpy(next.prev_hash, prev->hash, HASH_LEN);
    uint8_t tx_hashes[MERKLE_MAX_LEAVES][HASH_LEN];
    for(size_t i = 0; i < cnt; i++) {
        tx_hash(&txs[i],tx_hashes[i]);
    }
    merkle_root(tx_hashes, next.tx_root, cnt);
    compute_hash(&next, next.hash);
    *out = next;
    return BLOCK_OK;
}

void print_block(const Block *block) {
    char hash_hex[(HASH_LEN << 1) + 1];
    to_hex(block->hash, HASH_LEN, hash_hex);
    char prev_hash_hex[(HASH_LEN << 1) + 1];
    to_hex(block->prev_hash, HASH_LEN, prev_hash_hex);
    printf("INDEX=%lld|TIMESTAMP=%lld|HASH=%s|PREV_HASH=%s\n", 
            block->index, (long long)block->timestamp, hash_hex, prev_hash_hex);

}

const char *block_result_str(BlockResult result) {
    switch (result) {
    case BLOCK_OK:               return "ok";
    case BLOCK_ERR_TOO_MANY_TXS: return "too many transactions";
    }
    return "unknown result";
}
