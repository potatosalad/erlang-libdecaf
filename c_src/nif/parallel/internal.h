#ifndef LIBDECAF_NIF_PARALLEL_INTERNAL_H
#define LIBDECAF_NIF_PARALLEL_INTERNAL_H

#include "operation.h"
#include <stdatomic.h>

#define LIBDECAF_NIF_PARALLEL_WINDOW (256)
#define LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT (1024)

typedef struct libdecaf_nif_parallel_node_s {
    struct libdecaf_nif_parallel_node_s *next;
    libdecaf_nif_parallel_operation_t *operation;
    size_t index;
} libdecaf_nif_parallel_node_t;

typedef struct {
    _Atomic(libdecaf_nif_parallel_node_t *) incoming;
    libdecaf_nif_parallel_node_t *pending;
    atomic_flag reader;
    atomic_bool cleanup;
    atomic_size_t size;
} libdecaf_nif_parallel_queue_t;

typedef struct {
    atomic_size_t references;
    atomic_size_t next_router;
    unsigned int count;
    ERL_NIF_TERM names[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];
    libdecaf_nif_parallel_queue_t queues[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];
} libdecaf_nif_parallel_pool_t;

typedef struct {
    libdecaf_nif_parallel_node_t node;
    atomic_bool ready;
    uint8_t chaining[64];
} libdecaf_nif_parallel_result_t;

struct libdecaf_nif_parallel_operation_s {
    libdecaf_nif_parallel_pool_t *pool;
    ErlNifEnv *work_env;
    ERL_NIF_TERM state, reference;
    ErlNifPid owner;
    ErlNifMonitor monitor;
    ErlNifBinary input;
    size_t offset, window_offset, block_size, count, joined, output_length;
    libdecaf_nif_parallel_leaf_t leaf;
    atomic_size_t completed;
    atomic_bool cancelled, notified;
    bool monitored, finished, finish;
    libdecaf_nif_parallel_result_t results[LIBDECAF_NIF_PARALLEL_WINDOW];
};

extern void libdecaf_nif_parallel_pool_keep(libdecaf_nif_parallel_pool_t *pool);
extern void libdecaf_nif_parallel_pool_release(libdecaf_nif_parallel_pool_t *pool);
extern void libdecaf_nif_parallel_queue_push(libdecaf_nif_parallel_queue_t *queue, libdecaf_nif_parallel_node_t *head,
                                             libdecaf_nif_parallel_node_t *tail, size_t count);
extern void libdecaf_nif_parallel_queue_cleanup(libdecaf_nif_parallel_queue_t *queue);
extern void libdecaf_nif_parallel_wakeup(ErlNifEnv *env, libdecaf_nif_parallel_pool_t *pool, unsigned int router);
extern void libdecaf_nif_parallel_drain(ErlNifEnv *env, libdecaf_nif_parallel_pool_t *pool, unsigned int router, size_t max_rounds);

#endif
