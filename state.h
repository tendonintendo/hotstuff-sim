#ifndef STATE_H
#define STATE_H

#include <sodium.h>
#include <stddef.h>
#include "tx.h"

#define MAX_ACCOUNTS 64

typedef struct{
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint64_t balance;
    uint64_t nonce;
} Account;

typedef struct{
    size_t count;
    Account accounts[MAX_ACCOUNTS];
} State;

typedef enum {
    STATE_OK = 0,
    STATE_ERR_BAD_SIG,
    STATE_ERR_UNKNOWN_SENDER,
    STATE_ERR_UNKNOWN_RECEIVER,
    STATE_ERR_INSUFFICIENT_FUNDS,
    STATE_ERR_OVERFLOW,
    STATE_ERR_DUPLICATE,
    STATE_ERR_FULL,
    STATE_ERR_SELF_TRANSFER,
    STATE_ERR_INVALID_NONCE
} StateResult;

State state_init(void);
StateResult state_add(State *state, const uint8_t pk[crypto_sign_PUBLICKEYBYTES], const uint64_t balance);
Account* state_lookup(State *state, const uint8_t pk[crypto_sign_PUBLICKEYBYTES]);
StateResult state_apply_tx(State *state, const Tx *tx);
const char *state_result_str(StateResult result);

#endif