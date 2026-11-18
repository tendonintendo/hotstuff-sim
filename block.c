#include "block.h"

void compute_hash(const Block *block, uint8_t* output) {
    char payload[512];
    char prev_hash_hex[(SHA256_DIGEST_LENGTH << 1) + 1];
    to_hex(block->prev_hash, SHA256_DIGEST_LENGTH, prev_hash_hex);
    snprintf(payload, sizeof(payload), "INDEX=%lld|TIMESTAMP=%lld|PREV_HASH=%s", 
            block->index, (long long)block->timestamp, prev_hash_hex);

    SHA256((unsigned char*)payload, strlen(payload), output);
}

Block create_genesis_block(void) {
    Block genesis = {0};
    genesis.index = 0;
    memset(genesis.prev_hash, 0, SHA256_DIGEST_LENGTH);
    genesis.timestamp = time(NULL);
    compute_hash(&genesis, genesis.hash);
    return genesis;
}