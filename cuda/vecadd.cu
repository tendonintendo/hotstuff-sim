#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define CUDA_CHECK(call) do { \
    cudaError_t err_ = (call); \
    if (err_ != cudaSuccess) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(err_)); \
        exit(1); \
    } \
} while (0)

__global__ void add(const uint32_t *a, const uint32_t *b, uint32_t *out, size_t n) {
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if(i < n) out[i] = a[i] + b[i];
}

int main(void) {
    size_t n = 1000003;
    size_t bytes = n * sizeof(uint32_t);

    uint32_t *h_a = (uint32_t *)malloc(bytes);
    uint32_t *h_b = (uint32_t *)malloc(bytes);
    uint32_t *h_out = (uint32_t *)malloc(bytes);
    for(size_t i = 0; i < n; i++) h_a[i] = (uint32_t)i;
    for(size_t i = 0; i < n; i++) h_b[i] = 3*(uint32_t)i + 7;

    uint32_t *d_a, *d_b, *d_out;
    CUDA_CHECK(cudaMalloc((void **)&d_a, bytes));
    CUDA_CHECK(cudaMalloc((void **)&d_b, bytes));
    CUDA_CHECK(cudaMalloc((void **)&d_out, bytes));
    CUDA_CHECK(cudaMemcpy(d_a, h_a, bytes, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_b, h_b, bytes, cudaMemcpyHostToDevice));

    int threads = 256;
    int blocks = (int)((n + threads - 1) / threads);
    add<<<blocks, threads>>>(d_a, d_b, d_out, n);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaMemcpy(h_out, d_out, bytes, cudaMemcpyDeviceToHost));
    size_t mismatch = 0;
    for(size_t i = 0; i < n; i++) if(h_out[i] != h_a[i] + h_b[i]) mismatch++;
    printf("%zu MISMATCHES\n", mismatch);
    int status = 0;
    if(mismatch) status = 1;
    CUDA_CHECK(cudaFree(d_a));
    CUDA_CHECK(cudaFree(d_b));
    CUDA_CHECK(cudaFree(d_out));
    free(h_a);
    free(h_b);
    free(h_out);
    return status;
}