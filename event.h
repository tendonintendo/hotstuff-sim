#ifndef EVENT_H
#define EVENT_H

#include <stdint.h>
#include <stddef.h>
#define HEAP_CAP 4096

typedef enum {
    EV_DELIVER,
    EV_TIMER,
    EV_CRASH,
} EventType;

typedef enum {
    HEAP_OK = 0,
    HEAP_ERR_FULL,
    HEAP_ERR_EMPTY
} HeapResult;

typedef struct {
    uint64_t time;
    uint64_t seq;
    EventType type;
    uint8_t from;
    uint8_t node;
    uint16_t msg_idx;
} Event;

typedef struct{
    Event events[HEAP_CAP];
    uint64_t next_seq;
    size_t size;
} Heap;

void heap_init(Heap *heap);
HeapResult heap_push(Heap *heap, const Event *event);
HeapResult heap_pop(Event *out, Heap *heap);
HeapResult heap_peek(Event *out, const Heap *heap);

#endif