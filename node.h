#ifndef NODE_H
#define NODE_H

#include "sim.h"

SimResult node_on_message(Sim *sim, const uint8_t from, const uint8_t self, const uint8_t *bytes, const size_t len);
SimResult node_on_timer(Sim *sim, const uint8_t self);

#endif