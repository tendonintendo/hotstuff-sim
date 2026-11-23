#include "gpu_hash.h"
#include "sha256.cuh"
#include <stdio.h>

#define CUDA_TRY(call) do { \
    cudaError_t err_ = (call); \
    if (err_ != cudaSuccess) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(err_)); \
        goto fail; \
    } \
} while (0)

__global__ void sha256_kernel(uint8_t out[32], const uint8_t *in, size_t len) {
    sha256_dev(out, in, len);
}

__global__ void hash_headers_kernel(uint8_t *digests, const uint8_t *headers, size_t n) {
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if(i < n) {
        sha256_dev(digests + i * GPU_DIGEST_LEN, headers + i * GPU_HEADER_LEN, GPU_HEADER_LEN);
    }
}

GpuResult gpu_sha256(uint8_t out[32], const uint8_t *in, size_t len) {
    GpuResult r = GPU_ERR_CUDA;
    uint8_t *d_in = NULL;
    uint8_t *d_out = NULL;

    CUDA_TRY(cudaMalloc((void **)&d_out, GPU_DIGEST_LEN));
    if(len > 0) { 
        CUDA_TRY(cudaMalloc((void **)&d_in, len));
        CUDA_TRY(cudaMemcpy(d_in, in, len, cudaMemcpyHostToDevice));
    }

    sha256_kernel<<<1, 1>>>(d_out, d_in, len);
    CUDA_TRY(cudaGetLastError());
    CUDA_TRY(cudaDeviceSynchronize());

    CUDA_TRY(cudaMemcpy(out, d_out, GPU_DIGEST_LEN, cudaMemcpyDeviceToHost));
    r = GPU_OK;

fail:
    cudaFree(d_in);
    cudaFree(d_out);
    return r;
}

GpuResult gpu_hash_headers(uint8_t *digests, const uint8_t *headers, size_t n) {
    if(n == 0) return GPU_OK;
    
    GpuResult r = GPU_ERR_CUDA;
    uint8_t *d_headers = NULL;
    uint8_t *d_digests = NULL;
    size_t in_bytes = n * GPU_HEADER_LEN;
    size_t out_bytes = n * GPU_DIGEST_LEN;
    int threads = 256;
    int blocks = (int)((n + threads - 1) / threads);

    CUDA_TRY(cudaMalloc((void **)&d_digests, out_bytes));
    CUDA_TRY(cudaMalloc((void **)&d_headers, in_bytes));

    CUDA_TRY(cudaMemcpy(d_headers, headers, in_bytes, cudaMemcpyHostToDevice));

    hash_headers_kernel<<<blocks, threads>>>(d_digests, d_headers, n);
    CUDA_TRY(cudaGetLastError());
    CUDA_TRY(cudaDeviceSynchronize());

    CUDA_TRY(cudaMemcpy(digests, d_digests, out_bytes, cudaMemcpyDeviceToHost));

    r = GPU_OK;

fail:
    cudaFree(d_headers);
    cudaFree(d_digests);
    return r;
}