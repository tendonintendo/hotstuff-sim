#ifndef SHA256_CUH
#define SHA256_CUH

#include <stdint.h>
#include <stddef.h>

static __constant__ uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static __device__ __forceinline__ uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static __device__ __forceinline__ uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}
static __device__ __forceinline__ uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static __device__ __forceinline__ uint32_t big_sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static __device__ __forceinline__ uint32_t big_sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static __device__ __forceinline__ uint32_t small_sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static __device__ __forceinline__ uint32_t small_sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static __device__ __forceinline__ uint32_t load_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static __device__ __forceinline__ void store_be32(uint8_t *p, uint32_t x) {
    p[3] = (uint8_t)x;
    p[2] = (uint8_t)(x >> 8);
    p[1] = (uint8_t)(x >> 16);
    p[0] = (uint8_t)(x >> 24);
}

static __device__ void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    int t;
    for(t = 0; t < 64; t++) {
        if(t < 16) W[t] = load_be32(block + t * 4);
        else W[t] = small_sigma1(W[t - 2]) + W[t - 7] + small_sigma0(W[t - 15]) + W[t - 16];
    }

    uint32_t temp[8], T1, T2;
    memcpy(temp, state, sizeof(temp));

    for(t = 0; t < 64; t++) {
        T1 = temp[7] + big_sigma1(temp[4]) + ch(temp[4], temp[5], temp[6]) + K[t] + W[t];
        T2 = big_sigma0(temp[0]) + maj(temp[0], temp[1], temp[2]);
        temp[7] = temp[6];
        temp[6] = temp[5];
        temp[5] = temp[4];
        temp[4] = temp[3] + T1;
        temp[3] = temp[2];
        temp[2] = temp[1];
        temp[1] = temp[0];
        temp[0] = T1 + T2;
    }

    for(t = 0; t < 8; t++) state[t] += temp[t];
}

static __device__ void sha256_dev(uint8_t out[32], const uint8_t *in, size_t len) {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t full = len / 64;
    size_t rem = len % 64;
    uint8_t tail[128] = {0};
    uint64_t bits = len * 8;
    size_t k;
    for(k = 0; k < full; k++) sha256_compress(state, in + k * 64);

    memcpy(tail, in + full * 64, rem);
    tail[rem] = 0x80;

    size_t offset = rem < 56 ? 64 - 8 : 128 - 8;
    store_be32(tail + offset, (uint32_t)(bits >> 32));
    store_be32(tail + offset + 4, (uint32_t)bits);
    for(k = 0; k < (rem < 56 ? 1 : 2); k++) sha256_compress(state, tail + k * 64);

    for(k = 0; k < 8; k++) store_be32(out + k * 4, state[k]);
}

#endif