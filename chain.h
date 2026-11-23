#ifndef CHAIN_H
#define CHAIN_H
#include "block.h"
#include <stddef.h>

typedef struct{
    Block *blocks;
    size_t len, cap;
} Chain;

typedef enum {
    CHAIN_OK = 0,
    CHAIN_ERR_NOMEM,
    CHAIN_ERR_EMPTY,
    CHAIN_ERR_BAD_LINK,
    CHAIN_ERR_BAD_INDEX,
    CHAIN_ERR_BAD_HASH,
    CHAIN_ERR_BAD_GENESIS,
    CHAIN_ERR_BAD_BLOCK
} ChainResult;

Chain chain_init(void);
ChainResult chain_append(Chain *bc, const Tx txs[MAX_TXS], size_t cnt);
void chain_free(Chain *bc);
ChainResult validate_chain(const Chain *bc);
const char *chain_result_str(ChainResult result);
ChainResult chain_check_next(const Block *prev, const Block *b);

#endif
