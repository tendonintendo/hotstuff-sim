#include "sim.h"
#include <string.h>
#include "node.h"

SimResult sim_init(Sim *sim, const uint64_t seed, const uint64_t delay_min, const uint64_t delay_max, const size_t n) {
    if(delay_max < delay_min) return SIM_ERR_BAD_CONFIG;
    if(n <= 0 || n > SIM_MAX_NODES) return SIM_ERR_BAD_CONFIG;
    if(delay_max > UINT16_MAX) return SIM_ERR_BAD_CONFIG;
    sim->rng = prng_init(seed);
    sim->delay_min = delay_min;
    sim->delay_max = delay_max;
    sim->n = n;
    sim->free_count = SIM_POOL_CAP;
    sim->now = 0;
    sim->events_processed = 0;
    sim->delivered = 0;
    heap_init(&sim->heap);
    memset(&sim->crashed, 0, sizeof(sim->crashed));
    for(int i = 0; i < SIM_POOL_CAP; i++) sim->free[i] = i;
    return SIM_OK;
}

SimResult sim_send(Sim *sim, const uint8_t from, const uint8_t to, const uint8_t *bytes, const size_t len) {
    if(from >= sim->n || to >= sim->n) return SIM_ERR_BAD_NODE;
    if(len > SIM_MSG_MAX) return SIM_ERR_MSG_TOO_LONG;
    if(len <= 0) return SIM_ERR_MSG_LEN_ZERO;
    if(sim->free_count <= 0) return SIM_ERR_POOL_FULL;
    sim->free_count--;
    uint16_t idx = sim->free[sim->free_count];
    memcpy(sim->msg_pool[idx].bytes, bytes, len);
    sim->msg_pool[idx].len = len;
    Event e = {0};
    e.time = sim->now + (prng_next(&sim->rng) % (sim->delay_max - sim->delay_min + 1) + sim->delay_min);
    e.type = EV_DELIVER;
    e.from = from;
    e.node = to;
    e.msg_idx = idx;
    if(heap_push(&sim->heap, &e)) {
        sim->free[sim->free_count] = idx;
        sim->free_count++;
        return SIM_ERR_HEAP_FULL;
    }
    return SIM_OK;
}

SimResult sim_set_timer(Sim *sim, const uint8_t node, const uint64_t delay) {
    if(node >= sim->n) return SIM_ERR_BAD_NODE;
    Event e = {0};
    e.time = sim->now + delay;
    e.node = node;
    e.type = EV_TIMER;
    if(heap_push(&sim->heap, &e)) return SIM_ERR_HEAP_FULL;
    return SIM_OK;
}

SimResult sim_run(Sim *sim, const uint64_t timelimit) {
    Event e = {0};
    while(1) {
        if(heap_peek(&e,  &sim->heap)) return SIM_DONE_EMPTY;
        if(e.time > timelimit) return SIM_DONE_TIMELIMIT;
        heap_pop(&e, &sim->heap);
        if(e.time < sim->now) return SIM_ERR_TIME_BACKWARDS;
        sim->now = e.time;
        sim->events_processed++;
        SimResult r = SIM_OK;
        switch(e.type) {
            case EV_DELIVER:
                if(!sim->crashed[e.node]) {
                    sim->delivered++;
                    r = node_on_message(sim, e.from, e.node, sim->msg_pool[e.msg_idx].bytes, sim->msg_pool[e.msg_idx].len);
                }
                sim->free[sim->free_count] = e.msg_idx;
                sim->free_count++;
                if(r != SIM_OK) return r;
                break;
            case EV_TIMER:
                if(!sim->crashed[e.node]) {
                    r = node_on_timer(sim, e.node);
                }
                if(r != SIM_OK) return r;
                break;
            case EV_CRASH:
                sim->crashed[e.node] = 1;
                break;
        }
    }
}