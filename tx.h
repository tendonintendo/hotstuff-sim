#ifndef TX_H
#define TX_H

#include <sodium.h>
#include <stdint.h>
#include "hash.h"
#include "encode.h"

#define MAX_TXS 32
#define TX_MSG_LEN ((crypto_sign_PUBLICKEYBYTES << 1) + (sizeof(uint64_t) << 1))
#define TX_ENC_LEN (TX_MSG_LEN + crypto_sign_BYTES)

typedef enum {
    TX_OK = 0,
    TX_ERR_BAD_SIG,
    TX_ERR_FULL,
    TX_ERR_TRUNCATED
} TxResult;

const char *tx_result_str(TxResult result);

typedef struct{
    uint8_t from[crypto_sign_PUBLICKEYBYTES]; 
    uint8_t to[crypto_sign_PUBLICKEYBYTES];
    uint64_t amount;
    uint64_t nonce;
    uint8_t sig[crypto_sign_BYTES];
} Tx;

void tx_sign(Tx *tx, const uint8_t sk[crypto_sign_SECRETKEYBYTES]);
TxResult tx_verify(const Tx *tx);
void tx_hash(const Tx *tx, uint8_t out[HASH_LEN]);

TxResult tx_encode(Buf *out, const Tx *tx);
TxResult tx_decode(Tx *out, Reader *r);

#endif