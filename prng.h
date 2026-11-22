#ifndef PRNG_H
#define PRNG_H
#include <stdint.h>

typedef struct{
    uint64_t seed;
    uint64_t state;
} PRNG;

PRNG prng_init(uint64_t seed);
uint64_t prng_next(PRNG *prng);

#endif