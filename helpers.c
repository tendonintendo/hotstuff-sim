#include "helpers.h"

void to_hex(const uint8_t* hash, size_t length, char* output) {
    for (size_t i = 0; i < length; ++i) {
        sprintf(output + (i << 1), "%02x", hash[i]);
    }
    output[length << 1] = '\0';
}