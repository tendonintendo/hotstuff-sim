#include "merkle.h"
#include <string.h>

static void merkle_hash_pair(const uint8_t left[HASH_LEN], const uint8_t right[HASH_LEN], uint8_t out[HASH_LEN]) {
    uint8_t temp[(HASH_LEN << 1) + 1];
    temp[0] = 0x01;
    memcpy(temp + 1, left, HASH_LEN);
    memcpy(temp + 1 + HASH_LEN, right, HASH_LEN);
    hash_bytes(out, temp, sizeof(temp));
}

static void merkle_hash_leaf(const uint8_t leaf[HASH_LEN], uint8_t out[HASH_LEN]) {
    uint8_t temp[HASH_LEN + 1];
    temp[0] = 0x00;
    memcpy(temp + 1, leaf, HASH_LEN);
    hash_bytes(out, temp, sizeof(temp));
}

static int next_level(uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], const int _sz) {
    int odd = _sz % 2;
    for(int i = 0; i < _sz - odd; i += 2) {
        merkle_hash_pair(leaves[i], leaves[i + 1], leaves[i/2]);
    }
    if(odd) memcpy(leaves[_sz / 2], leaves[_sz - 1], HASH_LEN);
    return (_sz + 1) / 2;
}

MerkleResult merkle_root(const uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], uint8_t out[HASH_LEN], const size_t cnt) {
    if(!cnt) return MERKLE_ERR_ZERO_LEAVES;
    if(cnt > MERKLE_MAX_LEAVES) return MERKLE_ERR_MAX_LEAVES_EXCEEDED;

    uint8_t temp[MERKLE_MAX_LEAVES][HASH_LEN];
    for(size_t i = 0; i < cnt; i++) merkle_hash_leaf(leaves[i], temp[i]);

    int _sz = cnt;

    while(_sz > 1) {
        _sz = next_level(temp, _sz);
    }
    
    memcpy(out, temp[0], HASH_LEN);
    return MERKLE_OK;
}

MerkleResult merkle_proof(const uint8_t leaves[MERKLE_MAX_LEAVES][HASH_LEN], MerkleProof *proof, const size_t cnt, const size_t index) {
    if(!cnt) return MERKLE_ERR_ZERO_LEAVES;
    if(cnt > MERKLE_MAX_LEAVES) return MERKLE_ERR_MAX_LEAVES_EXCEEDED;
    if(index >= cnt) return MERKLE_ERR_BAD_INDEX;

    uint8_t temp[MERKLE_MAX_LEAVES][HASH_LEN];
    for(size_t i = 0; i < cnt; i++) merkle_hash_leaf(leaves[i], temp[i]);

    proof->count = 0;

    int _pos = index;
    int _sz = cnt;
    while(_sz > 1) {
        if(_pos % 2) {
            memcpy(proof->siblings[proof->count], temp[_pos - 1], HASH_LEN);
            proof->sibling_is_left[proof->count++] = 1;
        } else if(_pos + 1 < _sz) {
            memcpy(proof->siblings[proof->count], temp[_pos + 1], HASH_LEN);
            proof->sibling_is_left[proof->count++] = 0;
        }

        _sz = next_level(temp, _sz);
        _pos = _pos / 2;
    }
    return MERKLE_OK;
}

MerkleResult merkle_verify(const uint8_t leaf[HASH_LEN], const MerkleProof *proof, const uint8_t root[HASH_LEN]){
    if(proof->count > MERKLE_MAX_DEPTH) return MERKLE_ERR_MAX_DEPTH_EXCEEDED;
    uint8_t curr[HASH_LEN];
    merkle_hash_leaf(leaf, curr);

    for(size_t i = 0; i < proof->count; i++) {
        if(proof->sibling_is_left[i]) merkle_hash_pair(proof->siblings[i], curr, curr);
        else merkle_hash_pair(curr, proof->siblings[i], curr);
    }
    
    if(memcmp(curr, root, HASH_LEN)) return MERKLE_ERR_INVALID_PROOF;
    return MERKLE_OK;
}