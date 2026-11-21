#include <stdio.h>
#include <string.h>
#include <time.h>
#include "helpers.h"
#include "block.h"
#include "merkle.h"
#include "tx.h"

_Static_assert(MAX_TXS <= MERKLE_MAX_LEAVES, "MAX_TXS must fit in one Merkle tree");

void compute_hash(const Block *block, uint8_t* output) {
    uint8_t header[BLOCK_HEADER_LEN];
    Buf buf = init_enc_buf(header, BLOCK_HEADER_LEN);
    block_encode(&buf, block);
    hash_bytes(output, header, buf.len);
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

BlockResult block_encode(Buf *buf, const Block *b) {
    size_t len = buf->len;
    if(put_u64_le(buf, (uint64_t)b->index)) goto fail;
    if(put_u64_le(buf, (uint64_t)b->timestamp)) goto fail;
    if(put_bytes(buf, b->prev_hash, HASH_LEN)) goto fail;
    if(put_bytes(buf, b->tx_root, HASH_LEN)) goto fail;
    return BLOCK_OK;

fail:
    buf->len = len;
    return BLOCK_ERR_FULL;
}

BlockResult block_decode(Block *out, Reader *r) {
    Block tmp = {0};
    uint64_t index, timestamp;
    if(get_u64_le(&index, r)) return BLOCK_ERR_TRUNCATED;
    if(get_u64_le(&timestamp, r)) return BLOCK_ERR_TRUNCATED;
    if(get_bytes(tmp.prev_hash, r, HASH_LEN)) return BLOCK_ERR_TRUNCATED;
    if(get_bytes(tmp.tx_root, r, HASH_LEN)) return BLOCK_ERR_TRUNCATED;
    tmp.index = (long long)index;
    tmp.timestamp = (time_t)timestamp;
    compute_hash(&tmp, tmp.hash);
    *out = tmp;
    return BLOCK_OK;
}

const char *block_result_str(BlockResult result) {
    switch (result) {
    case BLOCK_OK:               return "ok";
    case BLOCK_ERR_TOO_MANY_TXS: return "too many transactions";
    case BLOCK_ERR_FULL:         return "buffer full";
    case BLOCK_ERR_TRUNCATED:    return "truncated input";
    }
    return "unknown result";
}
