#include "sim.h"
#include "encode.h"
#include "node.h"
#define PING_LIMIT 10

SimResult node_on_message(Sim *sim, const uint8_t from, const uint8_t self, const uint8_t *bytes, const size_t len){
    Reader r = init_enc_reader(bytes, len);
    uint64_t counter;
    if(get_u64_le(&counter, &r)) return SIM_ERR_BAD_MSG;
    if(counter >= PING_LIMIT) return SIM_OK;
    uint8_t out[8];
    Buf buf = init_enc_buf(out, sizeof(out));
    put_u64_le(&buf, counter + 1);
    return sim_send(sim, self, from, out, buf.len);
}

SimResult node_on_timer(Sim *sim, const uint8_t self) {
    (void) sim;
    (void) self;
    return SIM_OK;
}