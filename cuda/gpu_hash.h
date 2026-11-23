#ifndef GPU_HASH_H
#define GPU_HASH_H

#include <stdint.h>
#include <stddef.h>
#define GPU_HEADER_LEN 80
#define GPU_DIGEST_LEN 32

typedef enum{
    GPU_OK = 0,
    GPU_ERR_CUDA
} GpuResult;

#ifdef __cplusplus
extern "C" {
#endif

GpuResult gpu_sha256(uint8_t out[32], const uint8_t *in, size_t len);
GpuResult gpu_hash_headers(uint8_t *digests, const uint8_t *headers, size_t n);

#ifdef __cplusplus
}
#endif

#endif
