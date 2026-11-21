#include <stdio.h>
#include <string.h>
#include "../block.h"
#include "../chain.h"
#include "../tx.h"
#include "../state.h"
#include "../merkle.h"
#include "../encode.h"

static int checks = 0;
static int failures = 0;

#define CHECK(cond)                                                 \
    do {                                                            \
        checks++;                                                   \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                           \
    } while (0)

/* Builds a chain with n blocks in total, genesis included. */
static Chain build_chain(size_t n) {
    Chain bc = chain_init();
    while (bc.blocks != NULL && bc.len < n) {
        if (chain_append(&bc, NULL, 0) != CHAIN_OK) break;
    }
    return bc;
}

/* Relinks and rehashes every block from i to the tip, as an attacker rewriting history would. */
static void reseal_from(Chain *bc, size_t i) {
    for (size_t j = i; j < bc->len; j++) {
        if (j > 0) memcpy(bc->blocks[j].prev_hash, bc->blocks[j - 1].hash, HASH_LEN);
        compute_hash(&bc->blocks[j], bc->blocks[j].hash);
    }
}

/* Hashing the same block twice gives the same digest. */
static void test_hash_deterministic(void) {
    Block b = create_genesis_block();
    uint8_t h1[HASH_LEN], h2[HASH_LEN];
    compute_hash(&b, h1);
    compute_hash(&b, h2);
    CHECK(memcmp(h1, h2, HASH_LEN) == 0);
}

/* Changing any single header field changes the digest. */
static void test_hash_covers_every_field(void) {
    Block b = create_genesis_block();
    uint8_t h[HASH_LEN];
    Block c;

    c = b;
    c.index += 1;
    compute_hash(&c, h);
    CHECK(memcmp(b.hash, h, HASH_LEN) != 0);

    c = b;
    c.timestamp += 1;
    compute_hash(&c, h);
    CHECK(memcmp(b.hash, h, HASH_LEN) != 0);

    c = b;
    c.prev_hash[0] ^= 1;
    compute_hash(&c, h);
    CHECK(memcmp(b.hash, h, HASH_LEN) != 0);
}

/* chain_init produces a valid one-block chain. */
static void test_init(void) {
    Chain bc = chain_init();
    CHECK(bc.blocks != NULL);
    if (bc.blocks == NULL) return;
    CHECK(bc.len == 1);
    CHECK(bc.cap >= bc.len);
    CHECK(bc.blocks[0].index == 0);
    CHECK(validate_chain(&bc) == CHAIN_OK);
    chain_free(&bc);
}

/* Growing far past the initial capacity keeps earlier blocks intact and indices sequential. */
static void test_growth(void) {
    Chain bc = build_chain(1);
    uint8_t genesis_hash[HASH_LEN];
    memcpy(genesis_hash, bc.blocks[0].hash, HASH_LEN);

    int appended = 1;
    for (int i = 0; i < 99; i++) {
        if (chain_append(&bc, NULL, 0) != CHAIN_OK) appended = 0;
    }
    CHECK(appended);
    CHECK(bc.len == 100);
    CHECK(bc.cap >= bc.len);
    CHECK(memcmp(bc.blocks[0].hash, genesis_hash, HASH_LEN) == 0);

    int sequential = 1;
    for (size_t i = 0; i < bc.len; i++) {
        if (bc.blocks[i].index != (long long)i) sequential = 0;
    }
    CHECK(sequential);
    CHECK(validate_chain(&bc) == CHAIN_OK);
    chain_free(&bc);
}

/* A freshly built 10-block chain validates. */
static void test_valid_chain(void) {
    Chain bc = build_chain(10);
    CHECK(bc.len == 10);
    CHECK(validate_chain(&bc) == CHAIN_OK);
    chain_free(&bc);
}

/* Editing block 5 without rehashing is caught by the hash recompute check. */
static void test_edit_block_fails(void) {
    Chain bc = build_chain(10);
    bc.blocks[5].timestamp += 1;
    CHECK(validate_chain(&bc) == CHAIN_ERR_BAD_HASH);
    chain_free(&bc);
}

/* Editing and rehashing only block 5 is caught by block 6's prev_hash link. */
static void test_edit_and_rehash_fails(void) {
    Chain bc = build_chain(10);
    bc.blocks[5].timestamp += 1;
    compute_hash(&bc.blocks[5], bc.blocks[5].hash);
    CHECK(validate_chain(&bc) == CHAIN_ERR_BAD_LINK);
    chain_free(&bc);
}

/* Editing genesis without rehashing is caught. */
static void test_edit_genesis_fails(void) {
    Chain bc = build_chain(10);
    bc.blocks[0].timestamp += 1;
    CHECK(validate_chain(&bc) == CHAIN_ERR_BAD_HASH);
    chain_free(&bc);
}

/* A wrong index survives the hash and link checks after resealing, so only the index check can catch it. */
static void test_index_check(void) {
    Chain bc = build_chain(10);
    bc.blocks[5].index = 42;
    reseal_from(&bc, 5);
    CHECK(validate_chain(&bc) == CHAIN_ERR_BAD_INDEX);
    chain_free(&bc);
}

/* A non-zero genesis prev_hash is caught even after resealing the whole chain. */
static void test_genesis_prev_hash_check(void) {
    Chain bc = build_chain(10);
    bc.blocks[0].prev_hash[0] = 1;
    reseal_from(&bc, 0);
    CHECK(validate_chain(&bc) == CHAIN_ERR_BAD_GENESIS);
    chain_free(&bc);
}

/* Rewriting block 5 and every later block passes: hash links alone cannot stop a full rewrite. */
static void test_full_rewrite_is_undetected(void) {
    Chain bc = build_chain(10);
    bc.blocks[5].timestamp += 1;
    reseal_from(&bc, 5);
    CHECK(validate_chain(&bc) == CHAIN_OK);
    chain_free(&bc);
}

/* An empty chain is rejected. */
static void test_empty_chain_invalid(void) {
    Chain empty = {0};
    CHECK(validate_chain(&empty) == CHAIN_ERR_EMPTY);
}

/* chain_free leaves the chain empty and is safe to call twice. */
static void test_free(void) {
    Chain bc = build_chain(3);
    chain_free(&bc);
    CHECK(bc.blocks == NULL);
    CHECK(bc.len == 0 && bc.cap == 0);
    chain_free(&bc);
    CHECK(validate_chain(&bc) == CHAIN_ERR_EMPTY);
}

/* A keypair standing in for one account. */
typedef struct {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
} Keys;

/* Generates a fresh random account. */
static Keys new_account(void) {
    Keys a;
    crypto_sign_keypair(a.pk, a.sk);
    return a;
}

/* Builds a tx with the given nonce and signs it with the sender's key. */
static Tx signed_tx_nonce(const Keys *from, const Keys *to, uint64_t amount, uint64_t nonce) {
    Tx tx = {0};
    memcpy(tx.from, from->pk, sizeof(tx.from));
    memcpy(tx.to, to->pk, sizeof(tx.to));
    tx.amount = amount;
    tx.nonce = nonce;
    tx_sign(&tx, from->sk);
    return tx;
}

/* Builds a signed tx with nonce 0, i.e. the sender's first transaction. */
static Tx signed_tx(const Keys *from, const Keys *to, uint64_t amount) {
    return signed_tx_nonce(from, to, amount, 0);
}

/* A correctly signed tx verifies. */
static void test_tx_valid(void) {
    Keys alice = new_account(), bob = new_account();
    Tx tx = signed_tx(&alice, &bob, 100);
    CHECK(tx_verify(&tx));
}

/* Ed25519 is deterministic: signing the same tx twice gives the same signature. */
static void test_tx_sign_deterministic(void) {
    Keys alice = new_account(), bob = new_account();
    Tx a = signed_tx(&alice, &bob, 100);
    Tx b = signed_tx(&alice, &bob, 100);
    CHECK(memcmp(a.sig, b.sig, sizeof(a.sig)) == 0);
}

/* Changing the amount after signing breaks the signature. */
static void test_tx_tamper_amount(void) {
    Keys alice = new_account(), bob = new_account();
    Tx tx = signed_tx(&alice, &bob, 100);
    tx.amount = 1000000;
    CHECK(!tx_verify(&tx));
}

/* Every one of the amount's 8 bytes is covered by the signature. */
static void test_tx_amount_every_byte_signed(void) {
    Keys alice = new_account(), bob = new_account();
    Tx tx = signed_tx(&alice, &bob, 100);
    int all_caught = 1;
    for (int i = 0; i < 8; i++) {
        Tx t = tx;
        t.amount ^= (uint64_t)1 << (8 * i);
        if (tx_verify(&t)) all_caught = 0;
    }
    CHECK(all_caught);
}

/* Redirecting the payment to another recipient breaks the signature. */
static void test_tx_tamper_to(void) {
    Keys alice = new_account(), bob = new_account(), mallory = new_account();
    Tx tx = signed_tx(&alice, &bob, 100);
    memcpy(tx.to, mallory.pk, sizeof(tx.to));
    CHECK(!tx_verify(&tx));
}

/* Claiming a different sender breaks the signature. */
static void test_tx_tamper_from(void) {
    Keys alice = new_account(), bob = new_account(), carol = new_account();
    Tx tx = signed_tx(&alice, &bob, 100);
    memcpy(tx.from, carol.pk, sizeof(tx.from));
    CHECK(!tx_verify(&tx));
}

/* Flipping a single bit of the signature makes it invalid. */
static void test_tx_tamper_sig(void) {
    Keys alice = new_account(), bob = new_account();
    Tx tx = signed_tx(&alice, &bob, 100);
    tx.sig[0] ^= 1;
    CHECK(!tx_verify(&tx));
}

/* Signing with a key that does not own the from address fails verification. */
static void test_tx_wrong_key(void) {
    Keys alice = new_account(), bob = new_account(), mallory = new_account();
    Tx tx = {0};
    memcpy(tx.from, alice.pk, sizeof(tx.from));
    memcpy(tx.to, bob.pk, sizeof(tx.to));
    tx.amount = 100;
    tx_sign(&tx, mallory.sk);
    CHECK(!tx_verify(&tx));
}

/* An all-zero, never-signed tx is rejected. */
static void test_tx_unsigned(void) {
    Tx tx = {0};
    CHECK(!tx_verify(&tx));
}

/* Builds a state holding alice and bob with the given starting balances. */
static State two_account_state(const Keys *alice, uint64_t a_bal, const Keys *bob, uint64_t b_bal) {
    State s = state_init();
    state_add(&s, alice->pk, a_bal);
    state_add(&s, bob->pk, b_bal);
    return s;
}

/* Returns the balance stored for pk, or UINT64_MAX if the account is missing. */
static uint64_t balance_of(State *s, const Keys *k) {
    Account *a = state_lookup(s, k->pk);
    return a ? a->balance : UINT64_MAX;
}

/* A fresh state holds no accounts. */
static void test_state_init_empty(void) {
    State s = state_init();
    CHECK(s.count == 0);
}

/* An added account can be looked up with its starting balance; an unknown key cannot. */
static void test_state_add_and_lookup(void) {
    Keys alice = new_account(), bob = new_account();
    State s = state_init();
    CHECK(state_add(&s, alice.pk, 500) == STATE_OK);
    CHECK(s.count == 1);
    Account *a = state_lookup(&s, alice.pk);
    CHECK(a != NULL && a->balance == 500);
    CHECK(state_lookup(&s, bob.pk) == NULL);
}

/* Adding the same key twice is rejected and leaves the state unchanged. */
static void test_state_add_duplicate(void) {
    Keys alice = new_account();
    State s = state_init();
    state_add(&s, alice.pk, 500);
    CHECK(state_add(&s, alice.pk, 999) == STATE_ERR_DUPLICATE);
    CHECK(s.count == 1);
    CHECK(balance_of(&s, &alice) == 500);
}

/* The state accepts exactly MAX_ACCOUNTS accounts and rejects one more. */
static void test_state_add_full(void) {
    State s = state_init();
    uint8_t pk[crypto_sign_PUBLICKEYBYTES] = {0};
    int all_ok = 1;
    for (int i = 0; i < MAX_ACCOUNTS; i++) {
        pk[0] = (uint8_t)i;
        if (state_add(&s, pk, 0) != STATE_OK) all_ok = 0;
    }
    CHECK(all_ok);
    CHECK(s.count == MAX_ACCOUNTS);
    pk[0] = 0xff;
    CHECK(state_add(&s, pk, 0) == STATE_ERR_FULL);
    CHECK(s.count == MAX_ACCOUNTS);
}

/* A valid transfer moves exactly the amount from sender to receiver. */
static void test_apply_valid(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 5);
    Tx tx = signed_tx(&alice, &bob, 30);
    CHECK(state_apply_tx(&s, &tx) == STATE_OK);
    CHECK(balance_of(&s, &alice) == 70);
    CHECK(balance_of(&s, &bob) == 35);
}

/* Spending the entire balance is allowed: the funds check is >=, not >. */
static void test_apply_exact_balance(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    Tx tx = signed_tx(&alice, &bob, 100);
    CHECK(state_apply_tx(&s, &tx) == STATE_OK);
    CHECK(balance_of(&s, &alice) == 0);
    CHECK(balance_of(&s, &bob) == 100);
}

/* A tx altered after signing is rejected and changes nothing. */
static void test_apply_bad_sig(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    State before = s;
    Tx tx = signed_tx(&alice, &bob, 10);
    tx.amount = 90;
    CHECK(state_apply_tx(&s, &tx) == STATE_ERR_BAD_SIG);
    CHECK(memcmp(&s, &before, sizeof(State)) == 0);
}

/* A validly signed tx from an account not in the state is rejected. */
static void test_apply_unknown_sender(void) {
    Keys alice = new_account(), bob = new_account(), carol = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    Tx tx = signed_tx(&carol, &bob, 10);
    CHECK(state_apply_tx(&s, &tx) == STATE_ERR_UNKNOWN_SENDER);
}

/* A tx to an account not in the state is rejected and does not debit the sender. */
static void test_apply_unknown_receiver(void) {
    Keys alice = new_account(), bob = new_account(), carol = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    State before = s;
    Tx tx = signed_tx(&alice, &carol, 10);
    CHECK(state_apply_tx(&s, &tx) == STATE_ERR_UNKNOWN_RECEIVER);
    CHECK(memcmp(&s, &before, sizeof(State)) == 0);
}

/* Spending more than the balance is rejected instead of wrapping around, and changes nothing. */
static void test_apply_insufficient_funds(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    State before = s;
    Tx tx = signed_tx(&alice, &bob, 101);
    CHECK(state_apply_tx(&s, &tx) == STATE_ERR_INSUFFICIENT_FUNDS);
    CHECK(memcmp(&s, &before, sizeof(State)) == 0);
}

/* Crediting a receiver past UINT64_MAX is rejected, and the sender is not debited. */
static void test_apply_overflow(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, UINT64_MAX - 5);
    State before = s;
    Tx tx = signed_tx(&alice, &bob, 6);
    CHECK(state_apply_tx(&s, &tx) == STATE_ERR_OVERFLOW);
    CHECK(memcmp(&s, &before, sizeof(State)) == 0);
}

/* Filling the receiver exactly to UINT64_MAX is allowed. */
static void test_apply_overflow_boundary(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, UINT64_MAX - 5);
    Tx tx = signed_tx(&alice, &bob, 5);
    CHECK(state_apply_tx(&s, &tx) == STATE_OK);
    CHECK(balance_of(&s, &bob) == UINT64_MAX);
}

/* Sending to yourself is rejected. */
static void test_apply_self_transfer(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    Tx tx = signed_tx(&alice, &alice, 10);
    CHECK(state_apply_tx(&s, &tx) == STATE_ERR_SELF_TRANSFER);
    CHECK(balance_of(&s, &alice) == 100);
}

/* Returns the nonce stored for k, or UINT64_MAX if the account is missing. */
static uint64_t nonce_of(State *s, const Keys *k) {
    Account *a = state_lookup(s, k->pk);
    return a ? a->nonce : UINT64_MAX;
}

/* Replaying the same signed tx is rejected: the sender is charged once, not twice (was the planned failure). */
static void test_replay_rejected(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    Tx tx = signed_tx(&alice, &bob, 30);
    CHECK(state_apply_tx(&s, &tx) == STATE_OK);
    State before = s;
    CHECK(state_apply_tx(&s, &tx) == STATE_ERR_INVALID_NONCE);
    CHECK(memcmp(&s, &before, sizeof(State)) == 0);
    CHECK(balance_of(&s, &alice) == 70);
    CHECK(balance_of(&s, &bob) == 30);
}

/* New accounts start at nonce 0; only the sender's nonce advances on success. */
static void test_nonce_increments_sender_only(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    CHECK(nonce_of(&s, &alice) == 0 && nonce_of(&s, &bob) == 0);
    Tx tx = signed_tx(&alice, &bob, 10);
    CHECK(state_apply_tx(&s, &tx) == STATE_OK);
    CHECK(nonce_of(&s, &alice) == 1);
    CHECK(nonce_of(&s, &bob) == 0);
}

/* A sender's transactions apply in sequence 0, 1, 2. */
static void test_nonce_sequence(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    int all_ok = 1;
    for (uint64_t n = 0; n < 3; n++) {
        Tx tx = signed_tx_nonce(&alice, &bob, 10, n);
        if (state_apply_tx(&s, &tx) != STATE_OK) all_ok = 0;
    }
    CHECK(all_ok);
    CHECK(nonce_of(&s, &alice) == 3);
    CHECK(balance_of(&s, &alice) == 70);
}

/* A tx with a nonce from the future is rejected and changes nothing. */
static void test_nonce_future_rejected(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    State before = s;
    Tx tx = signed_tx_nonce(&alice, &bob, 10, 5);
    CHECK(state_apply_tx(&s, &tx) == STATE_ERR_INVALID_NONCE);
    CHECK(memcmp(&s, &before, sizeof(State)) == 0);
}

/* A rejected tx does not consume the nonce: the same nonce works once the tx is valid. */
static void test_nonce_not_consumed_on_rejection(void) {
    Keys alice = new_account(), bob = new_account();
    State s = two_account_state(&alice, 100, &bob, 0);
    Tx too_much = signed_tx_nonce(&alice, &bob, 500, 0);
    CHECK(state_apply_tx(&s, &too_much) == STATE_ERR_INSUFFICIENT_FUNDS);
    CHECK(nonce_of(&s, &alice) == 0);
    Tx ok = signed_tx_nonce(&alice, &bob, 50, 0);
    CHECK(state_apply_tx(&s, &ok) == STATE_OK);
}

/* The nonce is covered by the signature, so an attacker cannot re-number a replay. */
static void test_tx_tamper_nonce(void) {
    Keys alice = new_account(), bob = new_account();
    Tx tx = signed_tx(&alice, &bob, 30);
    tx.nonce = 1;
    CHECK(!tx_verify(&tx));
}

/* Every one of the nonce's 8 bytes is covered by the signature. */
static void test_tx_nonce_every_byte_signed(void) {
    Keys alice = new_account(), bob = new_account();
    Tx tx = signed_tx(&alice, &bob, 30);
    int all_caught = 1;
    for (int i = 0; i < 8; i++) {
        Tx t = tx;
        t.nonce ^= (uint64_t)1 << (8 * i);
        if (tx_verify(&t)) all_caught = 0;
    }
    CHECK(all_caught);
}


/* Fills n distinct leaf hashes: leaf i is SHA-256 of the single byte i. */
static void make_leaves(uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint8_t b = (uint8_t)i;
        hash_bytes(leaves[i], &b, 1);
    }
}

/* Independent reference for a tree leaf: SHA-256(0x00 || leaf), computed without merkle.c. */
static void ref_leaf(const uint8_t in[HASH_LEN], uint8_t out[HASH_LEN]) {
    uint8_t buf[1 + HASH_LEN];
    buf[0] = 0x00;
    memcpy(buf + 1, in, HASH_LEN);
    hash_bytes(out, buf, sizeof(buf));
}

/* Independent reference for an internal node: SHA-256(0x01 || left || right), computed without merkle.c. */
static void ref_pair(const uint8_t l[HASH_LEN], const uint8_t r[HASH_LEN], uint8_t out[HASH_LEN]) {
    uint8_t buf[1 + 2 * HASH_LEN];
    buf[0] = 0x01;
    memcpy(buf + 1, l, HASH_LEN);
    memcpy(buf + 1 + HASH_LEN, r, HASH_LEN);
    hash_bytes(out, buf, sizeof(buf));
}

/* Computes the prefixed tree-leaf hashes L[i] = H(0x00 || leaves[i]) for the first n leaves. */
static void ref_leaves(const uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], uint8_t L[MERKLE_MAX_LEAVES][HASH_LEN], size_t n) {
    for (size_t i = 0; i < n; i++) ref_leaf(leaves[i], L[i]);
}

/* Zero leaves and too many leaves are rejected. */
static void test_merkle_root_bad_counts(void) {
    static uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN];
    CHECK(merkle_root(leaves, root, 0) == MERKLE_ERR_ZERO_LEAVES);
    CHECK(merkle_root(leaves, root, MERKLE_MAX_LEAVES + 1) == MERKLE_ERR_MAX_LEAVES_EXCEEDED);
}

/* The root of a single leaf is that leaf's prefixed hash H(0x00 || leaf). */
static void test_merkle_root_one_leaf(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN], want[HASH_LEN];
    make_leaves(leaves, 1);
    ref_leaf(leaves[0], want);
    CHECK(merkle_root(leaves, root, 1) == MERKLE_OK);
    CHECK(memcmp(root, want, HASH_LEN) == 0);
}

/* Roots for 2, 3, 4 and 5 leaves match trees built by hand; an odd last node is carried up unhashed. */
static void test_merkle_root_small_trees(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], L[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN], h01[HASH_LEN], h23[HASH_LEN], h0123[HASH_LEN], want[HASH_LEN];
    make_leaves(leaves, 5);
    ref_leaves(leaves, L, 5);
    ref_pair(L[0], L[1], h01);
    ref_pair(L[2], L[3], h23);
    ref_pair(h01, h23, h0123);

    CHECK(merkle_root(leaves, root, 2) == MERKLE_OK);
    CHECK(memcmp(root, h01, HASH_LEN) == 0);

    ref_pair(h01, L[2], want);
    CHECK(merkle_root(leaves, root, 3) == MERKLE_OK);
    CHECK(memcmp(root, want, HASH_LEN) == 0);

    CHECK(merkle_root(leaves, root, 4) == MERKLE_OK);
    CHECK(memcmp(root, h0123, HASH_LEN) == 0);

    ref_pair(h0123, L[4], want);
    CHECK(merkle_root(leaves, root, 5) == MERKLE_OK);
    CHECK(memcmp(root, want, HASH_LEN) == 0);
}

/* For every n in 1..17, changing any single leaf changes the root. */
static void test_merkle_root_covers_every_leaf(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN], tampered[HASH_LEN];
    int all_caught = 1;
    for (size_t n = 1; n <= 17; n++) {
        make_leaves(leaves, n);
        merkle_root(leaves, root, n);
        for (size_t i = 0; i < n; i++) {
            leaves[i][0] ^= 1;
            merkle_root(leaves, tampered, n);
            if (memcmp(root, tampered, HASH_LEN) == 0) all_caught = 0;
            leaves[i][0] ^= 1;
        }
    }
    CHECK(all_caught);
}

/* The maximum leaf count is accepted. */
static void test_merkle_root_max_leaves(void) {
    static uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN];
    make_leaves(leaves, MERKLE_MAX_LEAVES);
    CHECK(merkle_root(leaves, root, MERKLE_MAX_LEAVES) == MERKLE_OK);
}

/* CVE-2012-2459 (fixed): duplicating the odd last leaf used to make [a,b,c] and [a,b,c,c] share a root;
   carrying the odd node up unchanged makes their roots differ. */
static void test_merkle_cve_2012_2459_no_collision(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root3[HASH_LEN], root4[HASH_LEN];
    make_leaves(leaves, 3);
    memcpy(leaves[3], leaves[2], HASH_LEN);
    merkle_root(leaves, root3, 3);
    merkle_root(leaves, root4, 4);
    CHECK(memcmp(root3, root4, HASH_LEN) != 0);
}

/* For every n in 1..17 and every leaf, the generated proof verifies against the root. */
static void test_merkle_proof_roundtrip_all(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN];
    int all_ok = 1;
    for (size_t n = 1; n <= 17; n++) {
        make_leaves(leaves, n);
        merkle_root(leaves, root, n);
        for (size_t i = 0; i < n; i++) {
            MerkleProof p;
            if (merkle_proof(leaves, &p, n, i) != MERKLE_OK) all_ok = 0;
            if (merkle_verify(leaves[i], &p, root) != MERKLE_OK) all_ok = 0;
        }
    }
    CHECK(all_ok);
}

/* The proof for c in [a,b,c,d,e] is [d right, H(ab) left, e right], as traced by hand. */
static void test_merkle_proof_shape_middle(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], L[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t h01[HASH_LEN];
    MerkleProof p;
    make_leaves(leaves, 5);
    ref_leaves(leaves, L, 5);
    ref_pair(L[0], L[1], h01);
    CHECK(merkle_proof(leaves, &p, 5, 2) == MERKLE_OK);
    CHECK(p.count == 3);
    CHECK(memcmp(p.siblings[0], L[3], HASH_LEN) == 0 && p.sibling_is_left[0] == 0);
    CHECK(memcmp(p.siblings[1], h01, HASH_LEN) == 0 && p.sibling_is_left[1] == 1);
    CHECK(memcmp(p.siblings[2], L[4], HASH_LEN) == 0 && p.sibling_is_left[2] == 0);
}

/* The carried-up leaf e in [a,b,c,d,e] skips two levels, so its proof is just [H(abcd) left]. */
static void test_merkle_proof_shape_carried(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], L[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t h01[HASH_LEN], h23[HASH_LEN], h0123[HASH_LEN];
    MerkleProof p;
    make_leaves(leaves, 5);
    ref_leaves(leaves, L, 5);
    ref_pair(L[0], L[1], h01);
    ref_pair(L[2], L[3], h23);
    ref_pair(h01, h23, h0123);
    CHECK(merkle_proof(leaves, &p, 5, 4) == MERKLE_OK);
    CHECK(p.count == 1);
    CHECK(memcmp(p.siblings[0], h0123, HASH_LEN) == 0 && p.sibling_is_left[0] == 1);
}

/* A single-leaf tree has an empty proof, and the leaf verifies against that tree's root. */
static void test_merkle_proof_single_leaf(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN];
    MerkleProof p;
    make_leaves(leaves, 1);
    merkle_root(leaves, root, 1);
    CHECK(merkle_proof(leaves, &p, 1, 0) == MERKLE_OK);
    CHECK(p.count == 0);
    CHECK(merkle_verify(leaves[0], &p, root) == MERKLE_OK);
}

/* The largest tree gives depth-8 proofs for its first and last leaves. */
static void test_merkle_proof_max_depth(void) {
    static uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN];
    MerkleProof first, last;
    make_leaves(leaves, MERKLE_MAX_LEAVES);
    merkle_root(leaves, root, MERKLE_MAX_LEAVES);
    CHECK(merkle_proof(leaves, &first, MERKLE_MAX_LEAVES, 0) == MERKLE_OK);
    CHECK(merkle_proof(leaves, &last, MERKLE_MAX_LEAVES, MERKLE_MAX_LEAVES - 1) == MERKLE_OK);
    CHECK(first.count == MERKLE_MAX_DEPTH && last.count == MERKLE_MAX_DEPTH);
    CHECK(merkle_verify(leaves[0], &first, root) == MERKLE_OK);
    CHECK(merkle_verify(leaves[MERKLE_MAX_LEAVES - 1], &last, root) == MERKLE_OK);
}

/* merkle_proof rejects empty trees, oversized trees and out-of-range indices. */
static void test_merkle_proof_bad_inputs(void) {
    static uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    MerkleProof p;
    make_leaves(leaves, 4);
    CHECK(merkle_proof(leaves, &p, 0, 0) == MERKLE_ERR_ZERO_LEAVES);
    CHECK(merkle_proof(leaves, &p, MERKLE_MAX_LEAVES + 1, 0) == MERKLE_ERR_MAX_LEAVES_EXCEEDED);
    CHECK(merkle_proof(leaves, &p, 4, 4) == MERKLE_ERR_BAD_INDEX);
}

/* A valid proof fails for a different leaf, a different root, a changed sibling, a flipped side or a dropped step. */
static void test_merkle_verify_rejects_tampering(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN], other_root[HASH_LEN];
    MerkleProof p, t;
    make_leaves(leaves, 7);
    merkle_root(leaves, root, 7);
    merkle_proof(leaves, &p, 7, 2);
    CHECK(merkle_verify(leaves[2], &p, root) == MERKLE_OK);

    CHECK(merkle_verify(leaves[3], &p, root) == MERKLE_ERR_INVALID_PROOF);

    memcpy(other_root, root, HASH_LEN);
    other_root[0] ^= 1;
    CHECK(merkle_verify(leaves[2], &p, other_root) == MERKLE_ERR_INVALID_PROOF);

    t = p;
    t.siblings[1][5] ^= 1;
    CHECK(merkle_verify(leaves[2], &t, root) == MERKLE_ERR_INVALID_PROOF);

    t = p;
    t.sibling_is_left[0] = !t.sibling_is_left[0];
    CHECK(merkle_verify(leaves[2], &t, root) == MERKLE_ERR_INVALID_PROOF);

    t = p;
    t.count--;
    CHECK(merkle_verify(leaves[2], &t, root) == MERKLE_ERR_INVALID_PROOF);
}

/* A proof claiming more levels than the tree can have is rejected before any sibling is read. */
static void test_merkle_verify_rejects_oversized_count(void) {
    uint8_t leaf[HASH_LEN] = {0}, root[HASH_LEN] = {0};
    MerkleProof p = {0};
    p.count = MERKLE_MAX_DEPTH + 1;
    CHECK(merkle_verify(leaf, &p, root) == MERKLE_ERR_MAX_DEPTH_EXCEEDED);
    p.count = (size_t)-1;
    CHECK(merkle_verify(leaf, &p, root) == MERKLE_ERR_MAX_DEPTH_EXCEEDED);
}

/* Second-preimage forgery (fixed): without leaf/node prefixes, the internal node H(ab) could be passed
   off as a leaf with the one-step proof [H(cd) right] and verify against the root. With 0x00/0x01
   domain separation the verifier re-hashes any claimed leaf as H(0x00 || leaf), so it must fail. */
static void test_merkle_internal_node_forged_as_leaf(void) {
    uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], L[MERKLE_MAX_LEAVES][HASH_LEN];
    uint8_t root[HASH_LEN], h01[HASH_LEN], h23[HASH_LEN];
    MerkleProof forged = {0};
    make_leaves(leaves, 4);
    merkle_root(leaves, root, 4);
    ref_leaves(leaves, L, 4);
    ref_pair(L[0], L[1], h01);
    ref_pair(L[2], L[3], h23);

    forged.count = 1;
    memcpy(forged.siblings[0], h23, HASH_LEN);
    forged.sibling_is_left[0] = 0;
    CHECK(merkle_verify(h01, &forged, root) == MERKLE_ERR_INVALID_PROOF);
}

/* Fills n signed txs from alice to bob with distinct amounts and sequential nonces. */
static void make_txs(Tx txs[MAX_TXS], size_t n, const Keys *alice, const Keys *bob) {
    for (size_t i = 0; i < n; i++) txs[i] = signed_tx_nonce(alice, bob, 10 + i, i);
}

/* Computes the expected tx_root for n txs independently: merkle_root over each tx_hash. */
static void expected_tx_root(const Tx txs[MAX_TXS], size_t n, uint8_t out[HASH_LEN]) {
    static uint8_t hashes[MERKLE_MAX_LEAVES][HASH_LEN];
    for (size_t i = 0; i < n; i++) tx_hash(&txs[i], hashes[i]);
    merkle_root(hashes, out, n);
}

/* tx_hash is deterministic and covers every field, including the signature. */
static void test_tx_hash_covers_all_fields(void) {
    Keys alice = new_account(), bob = new_account();
    Tx tx = signed_tx(&alice, &bob, 30);
    uint8_t h[HASH_LEN], again[HASH_LEN], changed[HASH_LEN];
    tx_hash(&tx, h);
    tx_hash(&tx, again);
    CHECK(memcmp(h, again, HASH_LEN) == 0);

    Tx t = tx; t.amount++;          tx_hash(&t, changed); CHECK(memcmp(h, changed, HASH_LEN) != 0);
    t = tx;    t.nonce++;           tx_hash(&t, changed); CHECK(memcmp(h, changed, HASH_LEN) != 0);
    t = tx;    t.to[0] ^= 1;        tx_hash(&t, changed); CHECK(memcmp(h, changed, HASH_LEN) != 0);
    t = tx;    t.from[0] ^= 1;      tx_hash(&t, changed); CHECK(memcmp(h, changed, HASH_LEN) != 0);
    t = tx;    t.sig[63] ^= 1;      tx_hash(&t, changed); CHECK(memcmp(h, changed, HASH_LEN) != 0);
}

/* make_block sets tx_root to the Merkle root of the tx hashes, links to prev and increments index. */
static void test_make_block_with_txs(void) {
    Keys alice = new_account(), bob = new_account();
    Tx txs[MAX_TXS];
    uint8_t want[HASH_LEN], h[HASH_LEN];
    Block genesis = create_genesis_block(), b;
    make_txs(txs, 5, &alice, &bob);
    expected_tx_root(txs, 5, want);

    CHECK(make_block(&genesis, txs, 5, &b) == BLOCK_OK);
    CHECK(memcmp(b.tx_root, want, HASH_LEN) == 0);
    CHECK(memcmp(b.prev_hash, genesis.hash, HASH_LEN) == 0);
    CHECK(b.index == 1);
    compute_hash(&b, h);
    CHECK(memcmp(b.hash, h, HASH_LEN) == 0);
}

/* An empty block's tx_root is all zeros. */
static void test_make_block_empty(void) {
    Block genesis = create_genesis_block(), b;
    uint8_t zero[HASH_LEN] = {0};
    CHECK(make_block(&genesis, NULL, 0, &b) == BLOCK_OK);
    CHECK(memcmp(b.tx_root, zero, HASH_LEN) == 0);
}

/* More than MAX_TXS txs is rejected and the output block is left untouched. */
static void test_make_block_too_many(void) {
    static Tx txs[MAX_TXS + 1];
    Block genesis = create_genesis_block(), b, before;
    memset(&b, 0xab, sizeof(b));
    before = b;
    CHECK(make_block(&genesis, txs, MAX_TXS + 1, &b) == BLOCK_ERR_TOO_MANY_TXS);
    CHECK(memcmp(&b, &before, sizeof(Block)) == 0);
}

/* Changing any one transaction changes the block's tx_root and therefore its hash. */
static void test_tx_change_changes_block_hash(void) {
    Keys alice = new_account(), bob = new_account();
    Tx txs[MAX_TXS];
    Block genesis = create_genesis_block(), a, b;
    make_txs(txs, 4, &alice, &bob);
    make_block(&genesis, txs, 4, &a);
    txs[2] = signed_tx_nonce(&alice, &bob, 999, 2);
    make_block(&genesis, txs, 4, &b);
    CHECK(memcmp(a.tx_root, b.tx_root, HASH_LEN) != 0);
    CHECK(memcmp(a.hash, b.hash, HASH_LEN) != 0);
}

/* chain_append with txs produces a valid chain; an oversized block is rejected and len is unchanged. */
static void test_chain_append_with_txs(void) {
    Keys alice = new_account(), bob = new_account();
    static Tx txs[MAX_TXS + 1];
    make_txs(txs, MAX_TXS, &alice, &bob);
    Chain bc = chain_init();
    CHECK(chain_append(&bc, txs, 3) == CHAIN_OK);
    CHECK(chain_append(&bc, txs, MAX_TXS) == CHAIN_OK);
    CHECK(chain_append(&bc, NULL, 0) == CHAIN_OK);
    CHECK(bc.len == 4);
    CHECK(validate_chain(&bc) == CHAIN_OK);
    CHECK(chain_append(&bc, txs, MAX_TXS + 1) == CHAIN_ERR_BAD_BLOCK);
    CHECK(bc.len == 4);
    chain_free(&bc);
}

/* Returns true if every byte of p[0..n) equals v. */
static int all_bytes_are(const uint8_t *p, size_t n, uint8_t v) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != v) return 0;
    }
    return 1;
}

/* A fresh writer has nothing written and remembers the caller's storage and capacity. */
static void test_buf_init(void) {
    uint8_t storage[16];
    Buf b = init_enc_buf(storage, sizeof(storage));
    CHECK(b.data == storage);
    CHECK(b.len == 0);
    CHECK(b.cap == 16);
}

/* A fresh reader starts at the first byte of the caller's input. */
static void test_reader_init(void) {
    static const uint8_t input[5] = {1, 2, 3, 4, 5};
    Reader r = init_enc_reader(input, sizeof(input));
    CHECK(r.data == input);
    CHECK(r.len == 5);
    CHECK(r.offset == 0);
}

/* Consecutive puts land back to back, starting at byte 0. */
static void test_put_bytes_appends(void) {
    uint8_t storage[8];
    memset(storage, 0xAA, sizeof(storage));
    Buf b = init_enc_buf(storage, sizeof(storage));
    const uint8_t x[3] = {1, 2, 3};
    const uint8_t y[2] = {4, 5};
    CHECK(put_bytes(&b, x, sizeof(x)) == ENC_OK);
    CHECK(put_bytes(&b, y, sizeof(y)) == ENC_OK);
    CHECK(b.len == 5);
    const uint8_t want[5] = {1, 2, 3, 4, 5};
    CHECK(memcmp(storage, want, 5) == 0);
    CHECK(all_bytes_are(storage + 5, 3, 0xAA));
}

/* Filling to exactly cap succeeds; one byte more is rejected without writing. */
static void test_put_bytes_exact_cap_then_full(void) {
    uint8_t storage[10];
    memset(storage, 0xAA, sizeof(storage));
    Buf b = init_enc_buf(storage, 8);
    const uint8_t x[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t one = 9;
    CHECK(put_bytes(&b, x, 8) == ENC_OK);
    CHECK(b.len == 8);
    CHECK(put_bytes(&b, &one, 1) == ENC_ERR_FULL);
    CHECK(b.len == 8);
    CHECK(all_bytes_are(storage + 8, 2, 0xAA));
}

/* A put bigger than the remaining room is rejected even on a non-empty writer. */
static void test_put_bytes_partial_room_full(void) {
    uint8_t storage[8];
    Buf b = init_enc_buf(storage, sizeof(storage));
    const uint8_t x[6] = {0};
    CHECK(put_bytes(&b, x, 6) == ENC_OK);
    CHECK(put_bytes(&b, x, 3) == ENC_ERR_FULL);
    CHECK(b.len == 6);
    CHECK(put_bytes(&b, x, 2) == ENC_OK);
    CHECK(b.len == 8);
}

/* Lengths that would wrap a naive len + n check are rejected. */
static void test_put_bytes_huge_len_rejected(void) {
    uint8_t storage[16];
    Buf b = init_enc_buf(storage, sizeof(storage));
    const uint8_t x[10] = {0};
    CHECK(put_bytes(&b, x, 10) == ENC_OK);
    CHECK(put_bytes(&b, x, SIZE_MAX) == ENC_ERR_FULL);
    CHECK(put_bytes(&b, x, SIZE_MAX - 5) == ENC_ERR_FULL);
    CHECK(b.len == 10);

    Buf empty = init_enc_buf(storage, sizeof(storage));
    CHECK(put_bytes(&empty, x, sizeof(storage) + 1) == ENC_ERR_FULL);
    CHECK(empty.len == 0);
}

/* A zero-length put always succeeds, even on a full writer, and changes nothing. */
static void test_put_bytes_zero_len(void) {
    uint8_t storage[4];
    Buf b = init_enc_buf(storage, sizeof(storage));
    const uint8_t x[4] = {1, 2, 3, 4};
    CHECK(put_bytes(&b, x, 0) == ENC_OK);
    CHECK(b.len == 0);
    CHECK(put_bytes(&b, x, 4) == ENC_OK);
    CHECK(put_bytes(&b, x, 0) == ENC_OK);
    CHECK(b.len == 4);

    Buf none = init_enc_buf(storage, 0);
    CHECK(put_bytes(&none, x, 0) == ENC_OK);
    CHECK(put_bytes(&none, x, 1) == ENC_ERR_FULL);
}

/* put_u64_le writes exactly 8 bytes, least significant first. */
static void test_put_u64_le_known_bytes(void) {
    uint8_t storage[16];
    Buf b = init_enc_buf(storage, sizeof(storage));
    CHECK(put_u64_le(&b, 1000) == ENC_OK);
    CHECK(put_u64_le(&b, 0x0102030405060708ULL) == ENC_OK);
    CHECK(b.len == 16);
    const uint8_t want[16] = {0xE8, 0x03, 0, 0, 0, 0, 0, 0,
                              0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    CHECK(memcmp(storage, want, 16) == 0);
}

/* A u64 after other data lands right after it and leaves earlier bytes intact. */
static void test_put_u64_le_after_bytes(void) {
    uint8_t storage[12];
    memset(storage, 0xAA, sizeof(storage));
    Buf b = init_enc_buf(storage, sizeof(storage));
    const uint8_t x[3] = {1, 2, 3};
    CHECK(put_bytes(&b, x, 3) == ENC_OK);
    CHECK(put_u64_le(&b, UINT64_MAX) == ENC_OK);
    CHECK(b.len == 11);
    CHECK(memcmp(storage, x, 3) == 0);
    CHECK(all_bytes_are(storage + 3, 8, 0xFF));
    CHECK(storage[11] == 0xAA);
}

/* A u64 that does not fit is rejected and writes nothing. */
static void test_put_u64_le_full(void) {
    uint8_t storage[16];
    memset(storage, 0xAA, sizeof(storage));
    Buf b = init_enc_buf(storage, 7);
    CHECK(put_u64_le(&b, 0) == ENC_ERR_FULL);
    CHECK(b.len == 0);
    CHECK(all_bytes_are(storage, 16, 0xAA));

    Buf c = init_enc_buf(storage, 15);
    CHECK(put_u64_le(&c, 0) == ENC_OK);
    CHECK(put_u64_le(&c, 0) == ENC_ERR_FULL);
    CHECK(c.len == 8);
    CHECK(all_bytes_are(storage + 8, 8, 0xAA));
}

/* Bytes read back in the order and with the content they were written. */
static void test_get_bytes_roundtrip(void) {
    uint8_t storage[8];
    Buf b = init_enc_buf(storage, sizeof(storage));
    const uint8_t x[3] = {9, 8, 7};
    const uint8_t y[5] = {6, 5, 4, 3, 2};
    CHECK(put_bytes(&b, x, 3) == ENC_OK);
    CHECK(put_bytes(&b, y, 5) == ENC_OK);

    Reader r = init_enc_reader(storage, b.len);
    uint8_t gx[3], gy[5];
    CHECK(get_bytes(gx, &r, 3) == ENC_OK);
    CHECK(r.offset == 3);
    CHECK(get_bytes(gy, &r, 5) == ENC_OK);
    CHECK(r.offset == 8);
    CHECK(memcmp(gx, x, 3) == 0);
    CHECK(memcmp(gy, y, 5) == 0);
}

/* Reading past the end fails and leaves both the reader and the output untouched. */
static void test_get_bytes_truncated(void) {
    static const uint8_t input[5] = {1, 2, 3, 4, 5};
    Reader r = init_enc_reader(input, sizeof(input));
    uint8_t out[8];
    memset(out, 0xAA, sizeof(out));
    CHECK(get_bytes(out, &r, 6) == ENC_ERR_TRUNCATED);
    CHECK(r.offset == 0);
    CHECK(all_bytes_are(out, 8, 0xAA));

    CHECK(get_bytes(out, &r, 3) == ENC_OK);
    CHECK(get_bytes(out, &r, 3) == ENC_ERR_TRUNCATED);
    CHECK(r.offset == 3);
    CHECK(get_bytes(out, &r, SIZE_MAX) == ENC_ERR_TRUNCATED);
    CHECK(r.offset == 3);
    CHECK(get_bytes(out, &r, 2) == ENC_OK);
    CHECK(r.offset == 5);
}

/* At the end of input a zero-length read succeeds and a one-byte read fails. */
static void test_get_bytes_at_end(void) {
    static const uint8_t input[2] = {1, 2};
    Reader r = init_enc_reader(input, sizeof(input));
    uint8_t out[2];
    CHECK(get_bytes(out, &r, 2) == ENC_OK);
    CHECK(get_bytes(out, &r, 0) == ENC_OK);
    CHECK(get_bytes(out, &r, 1) == ENC_ERR_TRUNCATED);
    CHECK(r.offset == 2);

    Reader empty = init_enc_reader(input, 0);
    CHECK(get_bytes(out, &empty, 0) == ENC_OK);
    CHECK(get_bytes(out, &empty, 1) == ENC_ERR_TRUNCATED);
}

/* Boundary u64 values survive an encode/decode round trip in sequence. */
static void test_u64_roundtrip(void) {
    const uint64_t vals[] = {0, 1, 0xFF, 0x100, 1000, 0x0102030405060708ULL,
                             0x8000000000000000ULL, UINT64_MAX - 1, UINT64_MAX};
    const size_t n = sizeof(vals) / sizeof(vals[0]);
    uint8_t storage[sizeof(vals)];
    Buf b = init_enc_buf(storage, sizeof(storage));
    int put_ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (put_u64_le(&b, vals[i]) != ENC_OK) put_ok = 0;
    }
    CHECK(put_ok);
    CHECK(b.len == n * 8);

    Reader r = init_enc_reader(storage, b.len);
    int all_match = 1;
    for (size_t i = 0; i < n; i++) {
        uint64_t got = 0;
        if (get_u64_le(&got, &r) != ENC_OK || got != vals[i]) all_match = 0;
    }
    CHECK(all_match);
    CHECK(r.offset == b.len);
}

/* Decoding overwrites the destination instead of merging with its old value. */
static void test_get_u64_le_ignores_old_value(void) {
    const uint8_t input[8] = {0xE8, 0x03, 0, 0, 0, 0, 0, 0};
    Reader r = init_enc_reader(input, sizeof(input));
    uint64_t got = UINT64_MAX;
    CHECK(get_u64_le(&got, &r) == ENC_OK);
    CHECK(got == 1000);

    Reader r2 = init_enc_reader(input, sizeof(input));
    uint64_t got2 = 5;
    CHECK(get_u64_le(&got2, &r2) == ENC_OK);
    CHECK(got2 == 1000);
}

/* A short u64 read fails and leaves the reader and destination untouched. */
static void test_get_u64_le_truncated(void) {
    static const uint8_t input[9] = {0};
    Reader r = init_enc_reader(input, 7);
    uint64_t got = 42;
    CHECK(get_u64_le(&got, &r) == ENC_ERR_TRUNCATED);
    CHECK(r.offset == 0);
    CHECK(got == 42);

    Reader r2 = init_enc_reader(input, 9);
    uint8_t skip[2];
    CHECK(get_bytes(skip, &r2, 2) == ENC_OK);
    CHECK(get_u64_le(&got, &r2) == ENC_ERR_TRUNCATED);
    CHECK(r2.offset == 2);
    CHECK(got == 42);
}

/* Bytes and u64s interleave correctly through a full write/read cycle. */
static void test_mixed_roundtrip(void) {
    uint8_t storage[3 + 8 + 2 + 8];
    Buf b = init_enc_buf(storage, sizeof(storage));
    const uint8_t x[3] = {0x11, 0x22, 0x33};
    const uint8_t y[2] = {0x44, 0x55};
    CHECK(put_bytes(&b, x, 3) == ENC_OK);
    CHECK(put_u64_le(&b, 0xDEADBEEFCAFEF00DULL) == ENC_OK);
    CHECK(put_bytes(&b, y, 2) == ENC_OK);
    CHECK(put_u64_le(&b, 7) == ENC_OK);
    CHECK(b.len == sizeof(storage));

    Reader r = init_enc_reader(storage, b.len);
    uint8_t gx[3], gy[2];
    uint64_t a = 0, c = 0;
    CHECK(get_bytes(gx, &r, 3) == ENC_OK);
    CHECK(get_u64_le(&a, &r) == ENC_OK);
    CHECK(get_bytes(gy, &r, 2) == ENC_OK);
    CHECK(get_u64_le(&c, &r) == ENC_OK);
    CHECK(memcmp(gx, x, 3) == 0);
    CHECK(a == 0xDEADBEEFCAFEF00DULL);
    CHECK(memcmp(gy, y, 2) == 0);
    CHECK(c == 7);
    CHECK(r.offset == r.len);
}

/* Every result has its own name. */
static void test_encode_result_str(void) {
    CHECK(strcmp(encode_result_str(ENC_OK), "unknown result") != 0);
    CHECK(strcmp(encode_result_str(ENC_ERR_FULL), "unknown result") != 0);
    CHECK(strcmp(encode_result_str(ENC_ERR_TRUNCATED), "unknown result") != 0);
    CHECK(strcmp(encode_result_str(ENC_ERR_FULL), encode_result_str(ENC_ERR_TRUNCATED)) != 0);
}

int main(void) {
    if(sodium_init() == -1) {
        printf("ERROR: SODIUM INIT FAILURE\n");
        return -1;
    }
    test_hash_deterministic();
    test_hash_covers_every_field();
    test_init();
    test_growth();
    test_valid_chain();
    test_edit_block_fails();
    test_edit_and_rehash_fails();
    test_edit_genesis_fails();
    test_index_check();
    test_genesis_prev_hash_check();
    test_full_rewrite_is_undetected();
    test_empty_chain_invalid();
    test_free();

    test_tx_valid();
    test_tx_sign_deterministic();
    test_tx_tamper_amount();
    test_tx_amount_every_byte_signed();
    test_tx_tamper_to();
    test_tx_tamper_from();
    test_tx_tamper_sig();
    test_tx_wrong_key();
    test_tx_unsigned();

    test_state_init_empty();
    test_state_add_and_lookup();
    test_state_add_duplicate();
    test_state_add_full();
    test_apply_valid();
    test_apply_exact_balance();
    test_apply_bad_sig();
    test_apply_unknown_sender();
    test_apply_unknown_receiver();
    test_apply_insufficient_funds();
    test_apply_overflow();
    test_apply_overflow_boundary();
    test_apply_self_transfer();
    test_replay_rejected();
    test_nonce_increments_sender_only();
    test_nonce_sequence();
    test_nonce_future_rejected();
    test_nonce_not_consumed_on_rejection();
    test_tx_tamper_nonce();
    test_tx_nonce_every_byte_signed();

    test_merkle_root_bad_counts();
    test_merkle_root_one_leaf();
    test_merkle_root_small_trees();
    test_merkle_root_covers_every_leaf();
    test_merkle_root_max_leaves();
    test_merkle_cve_2012_2459_no_collision();
    test_merkle_proof_roundtrip_all();
    test_merkle_proof_shape_middle();
    test_merkle_proof_shape_carried();
    test_merkle_proof_single_leaf();
    test_merkle_proof_max_depth();
    test_merkle_proof_bad_inputs();
    test_merkle_verify_rejects_tampering();
    test_merkle_verify_rejects_oversized_count();
    test_merkle_internal_node_forged_as_leaf();

    test_tx_hash_covers_all_fields();
    test_make_block_with_txs();
    test_make_block_empty();
    test_make_block_too_many();
    test_tx_change_changes_block_hash();
    test_chain_append_with_txs();

    test_buf_init();
    test_reader_init();
    test_put_bytes_appends();
    test_put_bytes_exact_cap_then_full();
    test_put_bytes_partial_room_full();
    test_put_bytes_huge_len_rejected();
    test_put_bytes_zero_len();
    test_put_u64_le_known_bytes();
    test_put_u64_le_after_bytes();
    test_put_u64_le_full();
    test_get_bytes_roundtrip();
    test_get_bytes_truncated();
    test_get_bytes_at_end();
    test_u64_roundtrip();
    test_get_u64_le_ignores_old_value();
    test_get_u64_le_truncated();
    test_mixed_roundtrip();
    test_encode_result_str();

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
