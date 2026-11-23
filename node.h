#ifndef NODE_H
#define NODE_H

#include "sim.h"

#define MSG_TAG_LEN 1
#define MSG_PING_LEN (MSG_TAG_LEN + 8)
#define MSG_PROPOSE_LEN (MSG_TAG_LEN + BLOCK_HEADER_LEN)
#define NODE_LEADER 0
#define NODE_PROPOSE_INTERVAL 100

_Static_assert(MSG_PROPOSE_LEN <= SIM_MSG_MAX, "proposal must fit in a pool slot");

typedef enum {
    MSG_PING = 1,
    MSG_PROPOSE = 2
} MsgType;

SimResult node_init(Sim *sim, const uint8_t self);
SimResult node_on_message(Sim *sim, const uint8_t from, const uint8_t self, const uint8_t *bytes, const size_t len);
SimResult node_on_timer(Sim *sim, const uint8_t self);

#endif