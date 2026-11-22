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
    size_t len = out->len;
    if(put_bytes(out, tx->from, crypto_sign_PUBLICKEYBYTES))  goto fail;
    if(put_bytes(out, tx->to, crypto_sign_PUBLICKEYBYTES)) goto fail;
    if(put_u64_le(out, tx->amount)) goto fail;
    if(put_u64_le(out, tx->nonce)) goto fail;
    if(put_bytes(out, tx->sig, crypto_sign_BYTES)) goto fail;
    return TX_OK;

fail:
    out->len = len;
    return TX_ERR_FULL;
}

TxResult tx_decode(Tx *out, Reader *r) {
    Tx temp = {0};
    size_t offset = r->offset;
    if(get_bytes(temp.from, r, crypto_sign_PUBLICKEYBYTES)) goto fail;
    if(get_bytes(temp.to, r, crypto_sign_PUBLICKEYBYTES)) goto fail;
    if(get_u64_le(&temp.amount, r)) goto fail;
    if(get_u64_le(&temp.nonce, r)) goto fail;
    if(get_bytes(temp.sig, r, crypto_sign_BYTES)) goto fail;
    *out = temp;
    return TX_OK;

fail:
    r->offset = offset;
    return TX_ERR_TRUNCATED;
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