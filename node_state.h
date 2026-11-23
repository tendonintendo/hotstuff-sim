#ifndef NODE_STATE_H
#define NODE_STATE_H

#include "block.h"

#define NODE_MAX_BLOCKS 128

typedef struct {
    Block blocks[NODE_MAX_BLOCKS];
    size_t len;
    uint64_t rejected;
} Node;

#endif