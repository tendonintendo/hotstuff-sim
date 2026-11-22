#include "prng.h"

PRNG prng_init(uint64_t seed) {
    PRNG rng = {0};
    rng.seed = seed;
    rng.state = seed;
    return rng;
}

uint64_t prng_next(PRNG *prng) {
    uint64_t state = prng->state;
    state += 0x9e3779b97f4a7c15ULL;
    prng->state = state;
    state = (state ^ (state >> 30)) * 0xbf58476d1ce4e5b9ULL;
    state = (state ^ (state >> 27)) * 0x94d049bb133111ebULL;
    state = state ^ (state >> 31);
    return state;
}