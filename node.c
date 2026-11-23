#include "sim.h"
#include "encode.h"
#include "node.h"
#include "chain.h"
#define PING_LIMIT 10

static size_t encode_propose(uint8_t out[MSG_PROPOSE_LEN], const Block *b) {
    Buf buf = init_enc_buf(out, MSG_PROPOSE_LEN);
    uint8_t tag = MSG_PROPOSE;
    put_bytes(&buf, &tag, MSG_TAG_LEN);
    block_encode(&buf, b);
    return buf.len;
}

static size_t encode_ping(uint8_t out[MSG_PING_LEN], const uint64_t counter) {
    Buf buf = init_enc_buf(out, MSG_PING_LEN);
    uint8_t tag = MSG_PING;
    put_bytes(&buf, &tag, MSG_TAG_LEN);
    put_u64_le(&buf, counter);
    return buf.len;
}

SimResult node_init(Sim *sim, const uint8_t self) {
    if(self >= sim->n) return SIM_ERR_BAD_NODE;
    Node *node = &sim->nodes[self];
    node->blocks[0] = create_genesis_block();
    node->len = 1;
    node->rejected = 0;
    if(self == NODE_LEADER) return sim_set_timer(sim, self, NODE_PROPOSE_INTERVAL);
    return SIM_OK;
}

SimResult node_on_message(Sim *sim, const uint8_t from, const uint8_t self, const uint8_t *bytes, const size_t len){
    Reader r = init_enc_reader(bytes, len);
    uint8_t tag;
    if(get_bytes(&tag, &r, MSG_TAG_LEN)) return SIM_ERR_BAD_MSG;
    switch(tag) {
        case MSG_PING: {
            uint64_t counter;
            if(get_u64_le(&counter, &r)) return SIM_ERR_BAD_MSG;
            if(counter >= PING_LIMIT) return SIM_OK;
            uint8_t ping[MSG_PING_LEN];
            size_t msg_len = encode_ping(ping, counter + 1);
            return sim_send(sim, self, from, ping, msg_len);
        }

        case MSG_PROPOSE: {
            Node *node = &sim->nodes[self];
            Block b;
            if(block_decode(&b, &r) != BLOCK_OK || r.offset != len) {
                node->rejected++;
                return SIM_OK;
            }
            if(from != NODE_LEADER || node->len == NODE_MAX_BLOCKS) {
                node->rejected++;
                return SIM_OK;
            }
            if(chain_check_next(&node->blocks[node->len - 1], &b) != CHAIN_OK) {
                node->rejected++;
                return SIM_OK;
            }
            node->blocks[node->len] = b;
            node->len++;
            return SIM_OK;
        }

        default:
            sim->nodes[self].rejected++;
            return SIM_OK;
    }
    return SIM_OK;
}

SimResult node_on_timer(Sim *sim, const uint8_t self) {
    if(self != NODE_LEADER) return SIM_OK;
    Node *node = &sim->nodes[self];
    if(node->len == 0) return SIM_ERR_BAD_NODE;
    if(node->len == NODE_MAX_BLOCKS) return SIM_OK;
    Block next;
    if(make_block(&node->blocks[node->len - 1], NULL, 0, sim->now, &next)) return SIM_ERR_BAD_BLOCK;
    node->blocks[node->len++] = next;
    uint8_t msg[MSG_PROPOSE_LEN];
    size_t msg_len = encode_propose(msg, &next);
    size_t j;
    SimResult r;
    for(j = 0; j < sim->n; j++) {
        if(j == self) continue;
        r = sim_send(sim, self, (uint8_t)j, msg, msg_len);
        if(r) return r;
    }

    return sim_set_timer(sim, self, NODE_PROPOSE_INTERVAL);
}