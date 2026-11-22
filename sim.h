#ifndef SIM_H
#define SIM_H

#include <stdint.h>
#include "event.h"
#include "prng.h"

#define SIM_MAX_NODES 32
#define SIM_MSG_MAX 4800
#define SIM_POOL_CAP 256

_Static_assert(SIM_POOL_CAP <= UINT16_MAX + 1, "pool slot indices must fit in uint16_t (Event.msg_idx, Sim.free)");
_Static_assert(SIM_MSG_MAX <= UINT16_MAX, "message length must fit in Slot.len (uint16_t)");
_Static_assert(SIM_MAX_NODES <= UINT8_MAX + 1, "node ids must fit in Event.node and Event.from (uint8_t)");

typedef enum{
    SIM_OK = 0,
    SIM_ERR_POOL_FULL,
    SIM_ERR_MSG_TOO_LONG,
    SIM_ERR_HEAP_FULL,
    SIM_DONE_TIMELIMIT,
    SIM_ERR_BAD_NODE,
    SIM_ERR_BAD_CONFIG,
    SIM_DONE_EMPTY,
    SIM_ERR_SEND,
    SIM_ERR_TIMER,
    SIM_ERR_TIME_BACKWARDS,
    SIM_ERR_MSG_LEN_ZERO,
    SIM_ERR_BAD_MSG
} SimResult;

typedef struct{
    uint16_t len;
    uint8_t bytes[SIM_MSG_MAX];
} Slot;

typedef struct{
    uint64_t now;
    Heap heap;
    PRNG rng;
    Slot msg_pool[SIM_POOL_CAP];
    size_t n;
    uint8_t crashed[SIM_MAX_NODES];
    uint16_t free[SIM_POOL_CAP];
    size_t free_count;
    uint64_t delay_min;
    uint64_t delay_max;
    uint64_t events_processed;
    uint64_t delivered;
} Sim;

SimResult sim_init(Sim *sim, const uint64_t seed, const uint64_t delay_min, const uint64_t delay_max, const size_t n);
SimResult sim_send(Sim *sim, const uint8_t from, const uint8_t to, const uint8_t *bytes, const size_t len);
SimResult sim_set_timer(Sim *sim, const uint8_t node, const uint64_t delay);
SimResult sim_run(Sim *sim, const uint64_t timelimit);

#endif