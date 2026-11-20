#include <stdio.h>
#include <string.h>
#include <time.h>
#include "helpers.h"
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
    genesis.timestamp = time(NULL);
    compute_hash(&genesis, genesis.hash);
    return genesis;
}

Block make_block(const Block *prev) {
    Block next = {0};
    next.timestamp = time(NULL);
    next.index = prev->index + 1;
    memcpy(next.prev_hash, prev->hash, SHA256_DIGEST_LENGTH);
    compute_hash(&next, next.hash);
    return next;
}