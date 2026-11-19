#include <stdio.h>
#include <string.h>
#include "block.h"

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
    return 0;
}