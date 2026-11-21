#include "block.h"
#include "chain.h"
#include "tx.h"
#include <stdlib.h>
#include <string.h>

Chain chain_init(void) {
    Chain bc = {0};
    bc.blocks = malloc(2 * sizeof(Block));
    if(bc.blocks == NULL) return bc;
    bc.blocks[0] = create_genesis_block();
    bc.cap = 2;
    bc.len = 1;
    return bc;
}

ChainResult chain_append(Chain *bc, const Tx txs[MAX_TXS], size_t cnt) {
    if(bc->len == bc->cap) {
        Block *temp = realloc(bc->blocks, sizeof(Block) * bc->cap << 1);
        if(temp != NULL){
            bc->blocks = temp;
            bc->cap = bc->cap << 1;
        } else return CHAIN_ERR_NOMEM;
    }
    if(make_block(&bc->blocks[bc->len - 1], txs, cnt, &bc->blocks[bc->len]) != BLOCK_OK) {
        return CHAIN_ERR_BAD_BLOCK;
    }
    bc->len++;
    return CHAIN_OK;
}

void chain_free(Chain *bc) {
    free(bc->blocks);
    bc->blocks = NULL;
    bc->len = bc->cap = 0;
}

ChainResult validate_chain(const Chain *bc) {
    if(bc->len == 0) return CHAIN_ERR_EMPTY;

    uint8_t buf[HASH_LEN];

    for(int i = bc->len - 1; i > 0; i--) {
        compute_hash(&bc->blocks[i], buf);

        if(memcmp(bc->blocks[i].prev_hash, bc->blocks[i-1].hash, HASH_LEN)) return CHAIN_ERR_BAD_LINK;
        if(bc->blocks[i].index != bc->blocks[i - 1].index + 1) return CHAIN_ERR_BAD_INDEX;
        if(memcmp(bc->blocks[i].hash, buf, HASH_LEN)) return CHAIN_ERR_BAD_HASH;
    }

    compute_hash(&bc->blocks[0], buf);

    if(memcmp(bc->blocks[0].hash, buf, HASH_LEN)) return CHAIN_ERR_BAD_HASH;
    if(bc->blocks[0].index != 0) return CHAIN_ERR_BAD_GENESIS;

    memset(buf, 0, HASH_LEN);
    if(memcmp(bc->blocks[0].prev_hash, buf, HASH_LEN)) return CHAIN_ERR_BAD_GENESIS;

    return CHAIN_OK;
}

const char *chain_result_str(ChainResult result) {
    switch (result) {
    case CHAIN_OK:              return "ok";
    case CHAIN_ERR_NOMEM:       return "out of memory";
    case CHAIN_ERR_EMPTY:       return "empty chain";
    case CHAIN_ERR_BAD_LINK:    return "prev_hash does not match previous block";
    case CHAIN_ERR_BAD_INDEX:   return "index not sequential";
    case CHAIN_ERR_BAD_HASH:    return "stored hash does not match contents";
    case CHAIN_ERR_BAD_GENESIS: return "malformed genesis block";
    case CHAIN_ERR_BAD_BLOCK:   return "block could not be built";
    }
    return "unknown result";
}
