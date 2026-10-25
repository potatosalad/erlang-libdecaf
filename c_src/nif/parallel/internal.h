#ifndef LIBDECAF_NIF_PARALLEL_INTERNAL_H
#define LIBDECAF_NIF_PARALLEL_INTERNAL_H

#include "operation.h"
#include <stdatomic.h>

#define LIBDECAF_NIF_PARALLEL_WINDOW (4096)
#define LIBDECAF_NIF_PARALLEL_WINDOWS (2)
#define LIBDECAF_NIF_PARALLEL_JOB_LEAVES (16)
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

/* Version 2 keeps one queue node/readiness mask per job and packs chaining
 * values separately. A split job requeues its existing node after taking a
 * local copy of the claimed range, rather than allocating a node per leaf. */
typedef struct {
    libdecaf_nif_parallel_node_t node;
    atomic_uint ready;
} libdecaf_nif_parallel_job_t;

typedef struct {
    size_t offset, count, joined;
    atomic_size_t completed;
    atomic_bool notified;
    bool active;
} libdecaf_nif_parallel_window_t;

typedef struct {
    size_t capacity, chaining_length;
    unsigned int current;
    libdecaf_nif_parallel_window_t windows[LIBDECAF_NIF_PARALLEL_WINDOWS];
    libdecaf_nif_parallel_job_t jobs[];
} libdecaf_nif_parallel_pipeline_t;

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
    uint8_t version, job_width;
    libdecaf_nif_parallel_result_t results[];
};

/* These bytes used to be zeroed padding. Keep old operation/resource layouts
 * readable during NIF takeover; version zero uses one queued node per leaf. */
_Static_assert(offsetof(libdecaf_nif_parallel_operation_t, results) ==
                   ((offsetof(libdecaf_nif_parallel_operation_t, finish) + 1 + _Alignof(libdecaf_nif_parallel_result_t) - 1) /
                    _Alignof(libdecaf_nif_parallel_result_t)) *
                       _Alignof(libdecaf_nif_parallel_result_t),
               "Parallel operation version must fit the legacy padding");

static inline libdecaf_nif_parallel_pipeline_t *
libdecaf_nif_parallel_pipeline(libdecaf_nif_parallel_operation_t *operation)
{
    return (void *)operation->results;
}

static inline libdecaf_nif_parallel_window_t *
libdecaf_nif_parallel_window(libdecaf_nif_parallel_operation_t *operation, size_t index)
{
    libdecaf_nif_parallel_pipeline_t *pipeline = libdecaf_nif_parallel_pipeline(operation);
    return &pipeline->windows[index / pipeline->capacity];
}

static inline libdecaf_nif_parallel_job_t *
libdecaf_nif_parallel_job(libdecaf_nif_parallel_operation_t *operation, size_t index)
{
    return &libdecaf_nif_parallel_pipeline(operation)->jobs[index / LIBDECAF_NIF_PARALLEL_JOB_LEAVES];
}

static inline uint8_t *
libdecaf_nif_parallel_chaining(libdecaf_nif_parallel_operation_t *operation, size_t index)
{
    if (operation->version < 2)
        return operation->results[index].chaining;
    libdecaf_nif_parallel_pipeline_t *pipeline = libdecaf_nif_parallel_pipeline(operation);
    size_t jobs = pipeline->capacity / LIBDECAF_NIF_PARALLEL_JOB_LEAVES * LIBDECAF_NIF_PARALLEL_WINDOWS;
    return (uint8_t *)&pipeline->jobs[jobs] + index * pipeline->chaining_length;
}

static inline size_t
libdecaf_nif_parallel_job_size(const libdecaf_nif_parallel_node_t *node)
{
    libdecaf_nif_parallel_operation_t *operation = node->operation;
    size_t width = operation->job_width != 0 ? operation->job_width : 1;
    size_t count = width - node->index % width;
    size_t remaining;
    if (operation->version >= 2) {
        libdecaf_nif_parallel_pipeline_t *pipeline = libdecaf_nif_parallel_pipeline(operation);
        remaining = libdecaf_nif_parallel_window(operation, node->index)->count - node->index % pipeline->capacity;
    } else {
        remaining = operation->count - node->index;
    }
    return count < remaining ? count : remaining;
}

extern libdecaf_nif_parallel_pool_t *libdecaf_nif_parallel_pool_current(ErlNifEnv *env);
extern void libdecaf_nif_parallel_pool_keep(libdecaf_nif_parallel_pool_t *pool);
extern void libdecaf_nif_parallel_pool_release(libdecaf_nif_parallel_pool_t *pool, bool wrapped);
extern void libdecaf_nif_parallel_queue_push(libdecaf_nif_parallel_queue_t *queue, libdecaf_nif_parallel_node_t *head,
                                             libdecaf_nif_parallel_node_t *tail, size_t count);
extern void libdecaf_nif_parallel_queue_cleanup(libdecaf_nif_parallel_queue_t *queue);
extern bool libdecaf_nif_parallel_wakeup(ErlNifEnv *env, libdecaf_nif_parallel_pool_t *pool, unsigned int router);
extern size_t libdecaf_nif_parallel_drain(ErlNifEnv *env, libdecaf_nif_parallel_pool_t *pool, unsigned int router,
                                          size_t max_rounds);

#endif
