#include <stdio.h>
#include "chain.h"
int main(void) {
    if(sodium_init() == -1) {
        printf("ERROR: SODIUM INIT FAILURE\n");
        return -1;
    }
    Chain bc = chain_init();
    if(!bc.blocks) {
        printf("ERROR: CHAIN INIT\n");
        return 1;
    }

    for(int i = 0; i < 3; i++) {
        print_block(&bc.blocks[i]);
        if(chain_append(&bc, NULL, 0) != CHAIN_OK) {
            printf("ERROR: CHAIN APPEND\n");
            chain_free(&bc);
            return 1;
        }
    }
    print_block(&bc.blocks[bc.len - 1]);

    chain_free(&bc);
    return 0;
}