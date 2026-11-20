#include <stdio.h>
#include <string.h>
#include "block.h"
#include "chain.h"
int main(void) {
    Block genesis = create_genesis_block();
    uint8_t buf1[SHA256_DIGEST_LENGTH], buf2[SHA256_DIGEST_LENGTH];
    compute_hash(&genesis, buf1);
    compute_hash(&genesis, buf2);
    printf("%s\n", memcmp(buf1, buf2, SHA256_DIGEST_LENGTH) ? "FAIL" : "PASS");

    Block copy = genesis;
    copy.index = 1;
    compute_hash(&copy, copy.hash);
    printf("%s\n", memcmp(genesis.hash, copy.hash, SHA256_DIGEST_LENGTH) ? "PASS" : "FAIL");

    Chain bc = chain_init();
    if(!bc.blocks) {
        printf("ERROR: CHAIN INIT\n");
        return 1;
    }

    for(int i = 0; i < 3; i++) {
        if(!chain_append(&bc)) {
            printf("ERROR: CHAIN APPEND\n");
            return 1;
        }
    }

    printf("%s\n", validate_chain(&bc) == 1 ? "PASS" : "FAIL");

    bc.blocks[0].timestamp = 999;

    printf("%s\n", validate_chain(&bc) == 1 ? "FAIL" : "PASS");

    chain_free(&bc);
    return 0;
}