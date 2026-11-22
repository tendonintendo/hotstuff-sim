#include "event.h"

void heap_init(Heap *heap) {
    heap->next_seq = heap->size = 0;
}

static int event_before(const Event *a, const Event *b) {
    return a->time < b->time || 
        (a->time == b->time && a->seq < b->seq);
}

HeapResult heap_push(Heap *heap, const Event *event){
    if(heap->size == HEAP_CAP) return HEAP_ERR_FULL;

    size_t idx = heap->size;
    heap->events[idx] = *event;
    heap->events[idx].seq = heap->next_seq;
    size_t parent_idx = (heap->size - 1)/2;
    Event tmp;

    while(idx != 0 && event_before(&heap->events[idx], &heap->events[parent_idx])) {
        tmp = heap->events[idx];
        heap->events[idx] = heap->events[parent_idx];
        heap->events[parent_idx] = tmp;
        idx = parent_idx;
        parent_idx = (parent_idx - 1)/2;
    }

    heap->size++;
    heap->next_seq++;
    return HEAP_OK;
}

HeapResult heap_pop(Event *out, Heap *heap) {
    if(heap->size == 0) return HEAP_ERR_EMPTY;

    size_t root = 0;
    *out = heap->events[root];
    heap->size--;
    size_t left = 2 * root + 1;
    size_t right = left + 1;
    size_t tmp, best;
    Event e;
    heap->events[root] = heap->events[heap->size];

    while(1) {
        left = 2 * root + 1;
        right = left + 1;
        best = root;

        if(left < heap->size && event_before(&heap->events[left], &heap->events[best])) {
            best = left;
        } 
        
        if(right < heap->size && event_before(&heap->events[right], &heap->events[best])) {
            best = right;
        }

        tmp = best;
        best = root;
        root = tmp;

        if(best == root) break;

        e = heap->events[best];
        heap->events[best] = heap->events[root];
        heap->events[root] = e;
    }
    return HEAP_OK;
}

HeapResult heap_peek(Event *out, const Heap *heap){
    if(heap->size == 0) return HEAP_ERR_EMPTY;
    *out = heap->events[0];
    return HEAP_OK;
}