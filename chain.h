#ifndef CHAIN_H
#define CHAIN_H
#include "block.h"
#include <string.h>

typedef struct{
    Block *blocks;
    size_t len, cap;
} Chain;

Chain chain_init(void);
int chain_append(Chain *bc);
void chain_free(Chain *bc);
int validate_chain(const Chain *bc);

#endif