#ifndef ENCODE_H
#define ENCODE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    ENC_OK = 0,
    ENC_ERR_FULL,
    ENC_ERR_TRUNCATED
} EncodeResult;

const char *encode_result_str(EncodeResult result);

typedef struct{
    uint8_t *data;
    size_t len;
    size_t cap;
} Buf;

typedef struct{
    const uint8_t *data;
    size_t len;
    size_t offset;
} Reader;

Reader init_enc_reader(const uint8_t *data, size_t len);
Buf init_enc_buf(uint8_t *data, size_t cap);

EncodeResult put_bytes(Buf *out, const uint8_t *data, size_t len);
EncodeResult get_bytes(uint8_t *out, Reader *read, size_t len);

EncodeResult put_u64_le(Buf *out, const uint64_t data);
EncodeResult get_u64_le(uint64_t *out, Reader *read);

#endif