#include "encode.h"
#include <string.h>

Reader init_enc_reader(const uint8_t *data, size_t len) {
    Reader temp = {0};
    temp.data = data;
    temp.len = len;
    return temp;
}

Buf init_enc_buf(uint8_t *data, size_t cap) {
    Buf temp = {0};
    temp.data = data;
    temp.cap = cap;
    return temp;
}

EncodeResult put_bytes(Buf *out, const uint8_t *data, size_t len){
    if(len > out->cap - out->len) return ENC_ERR_FULL;
    memcpy(out->data + out->len, data, len);
    out->len += len;
    return ENC_OK;
}

EncodeResult get_bytes(uint8_t *out, Reader *read, size_t len){
    if(len > read->len - read->offset) return ENC_ERR_TRUNCATED;
    memcpy(out, read->data + read->offset, len);
    read->offset += len;
    return ENC_OK;
}

EncodeResult put_u64_le(Buf *out, const uint64_t data){
    if(8 > out->cap - out->len) return ENC_ERR_FULL;
    for(int i = 0; i < 8; i++) {
        *(out->data + i + out->len) = (uint8_t)(data >> (8 * i));
    }
    out->len += 8;
    return ENC_OK;
}

EncodeResult get_u64_le(uint64_t *out, Reader *read){
    if(8 > read->len - read->offset) return ENC_ERR_TRUNCATED;
    uint64_t tmp = 0x00;
    for(int i = 0; i < 8; i++) {
        tmp |= (uint64_t) *(read->data + read->offset + i) << (8 * i);
    }
    read->offset += 8;
    *out = tmp;
    return ENC_OK;
}

const char *encode_result_str(EncodeResult result) {
    switch (result) {
    case ENC_OK:            return "ok";
    case ENC_ERR_FULL:      return "buffer full";
    case ENC_ERR_TRUNCATED: return "truncated input";
    }
    return "unknown result";
}
