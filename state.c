#include "state.h"
#include <string.h>

State state_init(void) {
    State state = {0};
    return state;
}

Account* state_lookup(State *state, const uint8_t pk[crypto_sign_PUBLICKEYBYTES]) {
    for(size_t i = 0; i < state->count; i++) {
        if(!memcmp(state->accounts[i].pk, pk, crypto_sign_PUBLICKEYBYTES)) return &state->accounts[i];
    }
    return NULL;
}
StateResult state_add(State *state, const uint8_t pk[crypto_sign_PUBLICKEYBYTES], const uint64_t balance) {
    if(state->count == MAX_ACCOUNTS) return STATE_ERR_FULL;
    if(state_lookup(state, pk)) return STATE_ERR_DUPLICATE;

    memcpy(state->accounts[state->count].pk, pk, crypto_sign_PUBLICKEYBYTES);
    state->accounts[state->count].balance = balance;
    state->accounts[state->count].nonce = 0;
    state->count++;
    return STATE_OK;
}

StateResult state_apply_tx(State *state, const Tx *tx) {
    if(tx_verify(tx)) return STATE_ERR_BAD_SIG;
    Account* from = state_lookup(state, tx->from);
    Account* to = state_lookup(state, tx->to);
    if(from == NULL) return STATE_ERR_UNKNOWN_SENDER;
    if(to == NULL) return STATE_ERR_UNKNOWN_RECEIVER;
    if(from->nonce != tx->nonce) return STATE_ERR_INVALID_NONCE;
    if(!memcmp(from, to, sizeof(Account))) return STATE_ERR_SELF_TRANSFER;
    if(from->balance < tx->amount) return STATE_ERR_INSUFFICIENT_FUNDS;
    if(to->balance > UINT64_MAX - tx->amount) return STATE_ERR_OVERFLOW;
    from->nonce++;
    from->balance -= tx->amount;
    to->balance += tx->amount;
    return STATE_OK;
}

const char *state_result_str(StateResult result) {
    switch (result) {
    case STATE_OK:                     return "ok";
    case STATE_ERR_BAD_SIG:            return "bad signature";
    case STATE_ERR_UNKNOWN_SENDER:     return "unknown sender";
    case STATE_ERR_UNKNOWN_RECEIVER:   return "unknown receiver";
    case STATE_ERR_INSUFFICIENT_FUNDS: return "insufficient funds";
    case STATE_ERR_OVERFLOW:           return "overflow";
    case STATE_ERR_FULL:               return "full";
    case STATE_ERR_DUPLICATE:          return "duplicate";
    case STATE_ERR_SELF_TRANSFER:      return "self transfer";
    case STATE_ERR_INVALID_NONCE:      return "invalid nonce";
    }
    return "unknown result";
}