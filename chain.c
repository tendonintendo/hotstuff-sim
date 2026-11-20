#include "block.h"
#include "chain.h"
#include <stdlib.h>

Chain chain_init(void) {
    Chain bc = {0};
    bc.blocks = malloc(2 * sizeof(Block));
    if(bc.blocks == NULL) return bc;
    bc.blocks[0] = create_genesis_block();
    bc.cap = 2;
    bc.len = 1;
    return bc;
}

int chain_append(Chain *bc) { 
    if(bc->len == bc->cap) {
        Block *temp = realloc(bc->blocks, sizeof(Block) * bc->cap << 1);
        if(temp != NULL){
            bc->blocks = temp;
            bc->cap = bc->cap << 1;
        } else return 0;
    }
    bc->blocks[bc->len] = make_block(&bc->blocks[bc->len - 1]);
    bc->len++;
    return 1;
}

void chain_free(Chain *bc) {
    free(bc->blocks);
}

int validate_chain(const Chain *bc) {
    if(bc->len == 0) return 0;

    uint8_t buf[SHA256_DIGEST_LENGTH];

    for(int i = bc->len - 1; i > 0; i--) {
        compute_hash(&bc->blocks[i], buf);
        
        if(memcmp(bc->blocks[i].prev_hash, bc->blocks[i-1].hash, SHA256_DIGEST_LENGTH)) return 0;
        if(bc->blocks[i].index != bc->blocks[i - 1].index + 1) return 0;
        if(memcmp(bc->blocks[i].hash, buf, SHA256_DIGEST_LENGTH)) return 0;
    }

    compute_hash(&bc->blocks[0], buf);

    if(memcmp(bc->blocks[0].hash, buf, SHA256_DIGEST_LENGTH)) return 0;
    if(bc->blocks[0].index != 0) return 0;
    
    memset(buf, 0, SHA256_DIGEST_LENGTH);
    if(memcmp(bc->blocks[0].prev_hash, buf, SHA256_DIGEST_LENGTH)) return 0;
    
    return 1;
}