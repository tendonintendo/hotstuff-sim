#include "tx.h"
#include "hash.h"
#include <string.h>

static void write_tx(const Tx *tx, uint8_t out[TX_MSG_LEN]) {
    memcpy(out, tx->from, sizeof(tx->from));
    memcpy(out + crypto_sign_PUBLICKEYBYTES, tx->to, sizeof(tx->to));

    for(int i = 0; i < 8; i++) {
        out[(crypto_sign_PUBLICKEYBYTES << 1) + i] = (uint8_t)(tx->amount >> (8 * i));
    }

    for(int i = 0; i < 8; i++) {
        out[(crypto_sign_PUBLICKEYBYTES << 1) + i + sizeof(uint64_t)] = (uint8_t)(tx->nonce >> (8 * i));
    }
}

void tx_sign(Tx *tx, const uint8_t sk[crypto_sign_SECRETKEYBYTES]) {
    uint8_t buf[TX_MSG_LEN];
    write_tx(tx, buf);
    crypto_sign_detached(tx->sig, NULL, buf, sizeof(buf), sk);
}

int tx_verify(const Tx *tx) {
    uint8_t buf[TX_MSG_LEN];
    write_tx(tx, buf);
    
    if(crypto_sign_verify_detached(tx->sig, buf, sizeof(buf), tx->from)) {
        return 0;
    }

    return 1;
}

void tx_hash(const Tx *tx, uint8_t out[HASH_LEN]) {
    uint8_t buf[TX_MSG_LEN + crypto_sign_BYTES];
    write_tx(tx, buf);
    memcpy(buf + TX_MSG_LEN, tx->sig, crypto_sign_BYTES);
    hash_bytes(out, buf, sizeof(buf));
}