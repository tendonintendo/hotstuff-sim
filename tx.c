#include "tx.h"
#include "hash.h"
#include <string.h>

static void write_tx(const Tx *tx, uint8_t out[TX_MSG_LEN]) {
    Buf buf = init_enc_buf(out, TX_MSG_LEN);
    put_bytes(&buf, tx->from, crypto_sign_PUBLICKEYBYTES);
    put_bytes(&buf, tx->to, crypto_sign_PUBLICKEYBYTES);
    put_u64_le(&buf, tx->amount);
    put_u64_le(&buf, tx->nonce);
}

void tx_sign(Tx *tx, const uint8_t sk[crypto_sign_SECRETKEYBYTES]) {
    uint8_t buf[TX_MSG_LEN];
    write_tx(tx, buf);
    crypto_sign_detached(tx->sig, NULL, buf, sizeof(buf), sk);
}

TxResult tx_verify(const Tx *tx) {
    uint8_t buf[TX_MSG_LEN];
    write_tx(tx, buf);

    if(crypto_sign_verify_detached(tx->sig, buf, sizeof(buf), tx->from)) {
        return TX_ERR_BAD_SIG;
    }

    return TX_OK;
}

void tx_hash(const Tx *tx, uint8_t out[HASH_LEN]) {
    uint8_t buf[TX_MSG_LEN + crypto_sign_BYTES];
    write_tx(tx, buf);
    memcpy(buf + TX_MSG_LEN, tx->sig, crypto_sign_BYTES);
    hash_bytes(out, buf, sizeof(buf));
}

TxResult tx_encode(Buf *out, const Tx *tx) {
    if(put_bytes(out, tx->from, crypto_sign_PUBLICKEYBYTES)) return TX_ERR_FULL;
    if(put_bytes(out, tx->to, crypto_sign_PUBLICKEYBYTES)) return TX_ERR_FULL;
    if(put_u64_le(out, tx->amount)) return TX_ERR_FULL;
    if(put_u64_le(out, tx->nonce)) return TX_ERR_FULL;
    if(put_bytes(out, tx->sig, crypto_sign_BYTES)) return TX_ERR_FULL;
    return TX_OK;
}

TxResult tx_decode(Tx *out, Reader *r) {
    if(get_bytes(out->from, r, crypto_sign_PUBLICKEYBYTES)) return TX_ERR_TRUNCATED;
    if(get_bytes(out->to, r, crypto_sign_PUBLICKEYBYTES)) return TX_ERR_TRUNCATED;
    if(get_u64_le(&out->amount, r)) return TX_ERR_TRUNCATED;
    if(get_u64_le(&out->nonce, r)) return TX_ERR_TRUNCATED;
    if(get_bytes(out->sig, r, crypto_sign_BYTES)) return TX_ERR_TRUNCATED;
    return TX_OK;
}

/* Returns a human-readable name for a tx result, for logs and test output. */
const char *tx_result_str(TxResult result) {
    switch (result) {
    case TX_OK:            return "ok";
    case TX_ERR_BAD_SIG:   return "bad signature";
    case TX_ERR_FULL:      return "buffer full";
    case TX_ERR_TRUNCATED: return "truncated input";
    }
    return "unknown result";
}