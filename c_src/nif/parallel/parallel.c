#include "parallel.h"
#include "internal.h"
#include "leaf.h"
#include <decaf/common.h>

/* A new queue format must never be consumed by workers still executing the
 * old shared library. Retire pools with earlier layouts on upgrade; existing
 * operations keep their pool alive and drain it on their caller. */
typedef struct {
    atomic_size_t magic;
    libdecaf_nif_parallel_pool_t pool;
} libdecaf_nif_parallel_private_t;

libdecaf_nif_parallel_pool_t *
libdecaf_nif_parallel_pool_current(ErlNifEnv *env)
{
    libdecaf_nif_parallel_private_t *private = enif_priv_data(env);
    return &private->pool;
}

static _Atomic(ERL_NIF_TERM) libdecaf_nif_parallel_worker_names[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];

static void
libdecaf_nif_parallel_worker_atoms(ErlNifEnv *env, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++) {
        char name[sizeof("libdecaf_parallel_absorb_") + 20];
        enif_snprintf(name, sizeof(name), "libdecaf_parallel_absorb_%llu", (unsigned long long)i + 1);
        atomic_store_explicit(&libdecaf_nif_parallel_worker_names[i], enif_make_atom(env, name), memory_order_release);
    }
}

void
libdecaf_nif_parallel_pool_keep(libdecaf_nif_parallel_pool_t *pool)
{
    atomic_fetch_add_explicit(&pool->references, 1, memory_order_relaxed);
}

void
libdecaf_nif_parallel_pool_release(libdecaf_nif_parallel_pool_t *pool, bool wrapped)
{
    if (atomic_fetch_sub_explicit(&pool->references, 1, memory_order_acq_rel) == 1) {
        void *allocation = wrapped ? (void *)((char *)pool - offsetof(libdecaf_nif_parallel_private_t, pool)) : (void *)pool;
        decaf_bzero(allocation, wrapped ? sizeof(libdecaf_nif_parallel_private_t) : sizeof(*pool));
        enif_free(allocation);
    }
}

int
libdecaf_nif_parallel_load(ErlNifEnv *env, void **priv_data, void *old_priv_data)
{
    if (old_priv_data != NULL && atomic_load_explicit((atomic_size_t *)old_priv_data, memory_order_relaxed) == SIZE_MAX - 1) {
        libdecaf_nif_parallel_private_t *private = old_priv_data;
        libdecaf_nif_parallel_worker_atoms(env, private->pool.count);
        libdecaf_nif_parallel_pool_keep(&private->pool);
        *priv_data = private;
        return 0;
    }
    libdecaf_nif_parallel_private_t *private = enif_alloc(sizeof(*private));
    if (private == NULL)
        return -1;
    decaf_bzero(private, sizeof(*private));
    /* Version 2 job nodes and packed outputs must never reach a version 1
     * worker. Retire its pool; outstanding operations drain on their caller. */
    atomic_init(&private->magic, SIZE_MAX - 1);
    libdecaf_nif_parallel_pool_t *pool = &private->pool;
    atomic_init(&pool->references, 1);
    atomic_init(&pool->next_router, 0);
    ErlNifSysInfo info;
    enif_system_info(&info, sizeof(info));
    pool->count = info.scheduler_threads > 0 ? (unsigned int)info.scheduler_threads : 1;
    if (pool->count > LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT)
        pool->count = LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT;
    for (unsigned int i = 0; i < pool->count; i++) {
        char name[sizeof("libdecaf_parallel_router_") + 20];
        int length = enif_snprintf(name, sizeof(name), "libdecaf_parallel_router_%llu", (unsigned long long)i + 1);
        if (length < 0 || (size_t)length >= sizeof(name)) {
            enif_free(private);
            return -1;
        }
        pool->names[i] = enif_make_atom(env, name);
        atomic_init(&pool->queues[i].incoming, NULL);
        atomic_flag_clear(&pool->queues[i].reader);
        atomic_init(&pool->queues[i].cleanup, false);
        atomic_init(&pool->queues[i].size, 0);
    }
    *priv_data = private;
    libdecaf_nif_parallel_worker_atoms(env, pool->count);
    return 0;
}

void
libdecaf_nif_parallel_unload(void *priv_data)
{
    if (priv_data != NULL)
        libdecaf_nif_parallel_pool_release(&((libdecaf_nif_parallel_private_t *)priv_data)->pool, true);
}

/* Producers publish a whole chain with one CAS. The consumer detaches incoming
 * chains atomically; nobody dereferences a concurrently reclaimed queue head.
 * A nonblocking reader claim also covers restarted routers and owner cleanup. */
void
libdecaf_nif_parallel_queue_push(libdecaf_nif_parallel_queue_t *queue, libdecaf_nif_parallel_node_t *head,
                                 libdecaf_nif_parallel_node_t *tail, size_t count)
{
    atomic_fetch_add_explicit(&queue->size, count, memory_order_relaxed);
    libdecaf_nif_parallel_node_t *old = atomic_load_explicit(&queue->incoming, memory_order_relaxed);
    do {
        tail->next = old;
    } while (!atomic_compare_exchange_weak_explicit(&queue->incoming, &old, head, memory_order_release, memory_order_relaxed));
}

static libdecaf_nif_parallel_node_t *
libdecaf_nif_parallel_queue_pop(libdecaf_nif_parallel_queue_t *queue)
{
    if (queue->pending == NULL)
        queue->pending = atomic_exchange_explicit(&queue->incoming, NULL, memory_order_acquire);
    libdecaf_nif_parallel_node_t *node = queue->pending;
    if (node != NULL) {
        queue->pending = node->next;
        atomic_fetch_sub_explicit(&queue->size, libdecaf_nif_parallel_job_size(node), memory_order_relaxed);
    }
    return node;
}

void
libdecaf_nif_parallel_queue_cleanup(libdecaf_nif_parallel_queue_t *queue)
{
    atomic_store(&queue->cleanup, true);
    for (;;) {
        if (atomic_flag_test_and_set_explicit(&queue->reader, memory_order_acquire))
            return;
        atomic_store(&queue->cleanup, false);
        libdecaf_nif_parallel_node_t *lists[2] = {queue->pending,
                                                  atomic_exchange_explicit(&queue->incoming, NULL, memory_order_acquire)};
        queue->pending = NULL;
        for (size_t i = 0; i < 2; i++) {
            libdecaf_nif_parallel_node_t *node = lists[i];
            while (node != NULL) {
                libdecaf_nif_parallel_node_t *next = node->next;
                if (atomic_load_explicit(&node->operation->cancelled, memory_order_acquire)) {
                    atomic_fetch_sub_explicit(&queue->size, libdecaf_nif_parallel_job_size(node), memory_order_relaxed);
                    enif_release_resource(node->operation);
                } else {
                    node->next = queue->pending;
                    queue->pending = node;
                }
                node = next;
            }
        }
        atomic_flag_clear_explicit(&queue->reader, memory_order_release);
        if (!atomic_load(&queue->cleanup))
            return;
    }
}

bool
libdecaf_nif_parallel_wakeup(ErlNifEnv *env, libdecaf_nif_parallel_pool_t *pool, unsigned int router)
{
    if (pool != libdecaf_nif_parallel_pool_current(env))
        return false;
    if (atomic_load_explicit(&pool->queues[router].size, memory_order_acquire) != 0) {
        ErlNifPid pid;
        ERL_NIF_TERM worker = atomic_load_explicit(&libdecaf_nif_parallel_worker_names[router], memory_order_acquire);
        if (enif_whereis_pid(env, worker, &pid) || enif_whereis_pid(env, pool->names[router], &pid)) {
            (void)enif_send(env, &pid, NULL, ATOM(wakeup));
            return true;
        }
        return false;
    }
    return true;
}

static const uint8_t *
libdecaf_nif_parallel_leaf_input(libdecaf_nif_parallel_operation_t *operation, size_t index)
{
    if (operation->version >= 2) {
        libdecaf_nif_parallel_pipeline_t *pipeline = libdecaf_nif_parallel_pipeline(operation);
        size_t offset = pipeline->windows[index / pipeline->capacity].offset;
        return operation->input.data + offset + index % pipeline->capacity * operation->block_size;
    }
    return operation->input.data + operation->window_offset + index * operation->block_size;
}

static void
libdecaf_nif_parallel_job_complete(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation, size_t index, size_t count)
{
    /* Once every job has published completion, the collector may reuse count
     * for the next window. Read it before this job's release, while that reuse
     * is still blocked by our outstanding completion. */
    libdecaf_nif_parallel_window_t *window = operation->version >= 2 ? libdecaf_nif_parallel_window(operation, index) : NULL;
    atomic_size_t *completed = window != NULL ? &window->completed : &operation->completed;
    atomic_bool *notified = window != NULL ? &window->notified : &operation->notified;
    size_t total = window != NULL ? window->count : operation->count;
    if (atomic_fetch_add_explicit(completed, count, memory_order_acq_rel) + count == total) {
        if (!atomic_load_explicit(&operation->cancelled, memory_order_acquire)) {
            ERL_NIF_TERM reference = enif_make_copy(env, operation->reference);
            (void)enif_send(env, &operation->owner, NULL, enif_make_tuple2(env, ATOM(libdecaf_parallel), reference));
        }
        /* Publish after sending so the collector can flush the only notification
         * for this window without leaving a late message in its mailbox. */
        atomic_store_explicit(notified, true, memory_order_release);
    }
    enif_release_resource(operation);
}

size_t
libdecaf_nif_parallel_drain(ErlNifEnv *env, libdecaf_nif_parallel_pool_t *pool, unsigned int router, size_t max_rounds)
{
    libdecaf_nif_parallel_queue_t *queue = &pool->queues[router];
    size_t processed = 0;
    while (max_rounds == 0 || processed < max_rounds) {
        if (!enif_is_current_process_alive(env) || atomic_flag_test_and_set_explicit(&queue->reader, memory_order_acquire))
            break;
        libdecaf_nif_parallel_node_t *node = libdecaf_nif_parallel_queue_pop(queue);
        size_t count = node != NULL ? libdecaf_nif_parallel_job_size(node) : 0;
        libdecaf_nif_parallel_operation_t *operation = node != NULL ? node->operation : NULL;
        size_t first = node != NULL ? node->index : 0;
        if (max_rounds != 0 && count > max_rounds - processed) {
            /* Preserve the exact leaf budget, including limits smaller than one
             * job. The remainder owns a separate reference before publication. */
            size_t take = max_rounds - processed;
            libdecaf_nif_parallel_node_t *rest;
            if (operation->version >= 2) {
                /* Keep only the range in local variables. Once republished,
                 * another worker may claim and advance this same job node. */
                rest = node;
                rest->index = first + take;
            } else {
                rest = &operation->results[first + take].node;
            }
            enif_keep_resource(operation);
            libdecaf_nif_parallel_queue_push(queue, rest, rest, count - take);
            count = take;
        }
        /* A job retains its operation independently. Hash outside the reader
         * claim so other workers can steal another short span from this queue. */
        atomic_flag_clear_explicit(&queue->reader, memory_order_release);
        if (atomic_load(&queue->cleanup))
            libdecaf_nif_parallel_queue_cleanup(queue);
        if (node == NULL)
            break;
        size_t end = first + count;
        if (!atomic_load_explicit(&operation->cancelled, memory_order_acquire)) {
            bool packed = operation->version >= 2;
            size_t block_size = operation->block_size;
            size_t stride =
                packed ? libdecaf_nif_parallel_pipeline(operation)->chaining_length : sizeof(libdecaf_nif_parallel_result_t);
            libdecaf_nif_parallel_leaf_t leaf = operation->leaf;
            const uint8_t *input = libdecaf_nif_parallel_leaf_input(operation, first);
            uint8_t *chaining = libdecaf_nif_parallel_chaining(operation, first);
            size_t index = first;
            unsigned int preferred_width = libdecaf_nif_parallel_leaf_width();
            while (end - index >= 2 && preferred_width >= 2) {
                unsigned int width = preferred_width;
                while (width > end - index)
                    width /= 2;
                const uint8_t *inputs[8];
                uint8_t *outputs[8];
                for (unsigned int lane = 0; lane < width; ++lane) {
                    inputs[lane] = input + (index + lane - first) * block_size;
                    outputs[lane] = chaining + (index + lane - first) * stride;
                }
                libdecaf_nif_parallel_leaf_hash_many(leaf, inputs, block_size, outputs, width);
                if (!packed) {
                    for (unsigned int lane = 0; lane < width; ++lane)
                        atomic_store_explicit(&operation->results[index + lane].ready, true, memory_order_release);
                }
                index += width;
            }
            for (; index < end; ++index) {
                libdecaf_nif_parallel_leaf_hash(leaf, input + (index - first) * block_size, block_size,
                                                chaining + (index - first) * stride);
                if (!packed)
                    atomic_store_explicit(&operation->results[index].ready, true, memory_order_release);
            }
            if (packed) {
                unsigned int mask = ((1u << count) - 1u) << (first % LIBDECAF_NIF_PARALLEL_JOB_LEAVES);
                atomic_uint *ready = &libdecaf_nif_parallel_job(operation, first)->ready;
                if (count == LIBDECAF_NIF_PARALLEL_JOB_LEAVES)
                    atomic_store_explicit(ready, mask, memory_order_release);
                else
                    atomic_fetch_or_explicit(ready, mask, memory_order_release);
            }
        }
        libdecaf_nif_parallel_job_complete(env, operation, first, count);
        processed += count;
    }
    libdecaf_nif_parallel_wakeup(env, pool, router);
    return processed;
}

ERL_NIF_TERM
libdecaf_nif_parallel_router_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argv;
    if (argc != 0)
        return enif_make_badarg(env);
    libdecaf_nif_parallel_pool_t *pool = libdecaf_nif_parallel_pool_current(env);
    size_t queued = 0;
    for (unsigned int i = 0; i < pool->count; i++)
        queued += atomic_load_explicit(&pool->queues[i].size, memory_order_relaxed);
    ERL_NIF_TERM keys[] = {ATOM(count), ATOM(limit), ATOM(names), ATOM(queued)};
    ERL_NIF_TERM values[] = {enif_make_uint(env, pool->count), enif_make_uint(env, LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT),
                             enif_make_list_from_array(env, pool->names, pool->count), enif_make_ulong(env, queued)};
    ERL_NIF_TERM info;
    if (!enif_make_map_from_arrays(env, keys, values, 4, &info))
        return EXCP_ERROR(env, "Could not create parallel router info");
    return info;
}

ERL_NIF_TERM
libdecaf_nif_parallel_absorb_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_parallel_pool_t *pool = libdecaf_nif_parallel_pool_current(env);
    unsigned int router;
    unsigned long max_rounds;
    if (argc != 2 || !enif_get_uint(env, argv[0], &router) || router == 0 || router > pool->count ||
        !enif_get_ulong(env, argv[1], &max_rounds))
        return EXCP_BADARG(env, "Expected a native parallel router number");
    /* Preserve the requested total budget, including zero's drain-until-idle
     * semantics, while handing the dirty scheduler back between short batches. */
    const size_t slice = 128;
    size_t processed = 0;
    for (unsigned int offset = 0; offset < pool->count && processed < slice && enif_is_current_process_alive(env); offset++) {
        if (max_rounds != 0 && processed == max_rounds)
            break;
        size_t budget = slice - processed;
        if (max_rounds != 0 && budget > max_rounds - processed)
            budget = max_rounds - processed;
        processed += libdecaf_nif_parallel_drain(env, pool, (router - 1 + offset) % pool->count, budget);
    }
    if (processed != 0 && (max_rounds == 0 || (processed == slice && processed < max_rounds)) &&
        enif_is_current_process_alive(env)) {
        ERL_NIF_TERM arguments[] = {argv[0], enif_make_ulong(env, max_rounds == 0 ? 0 : max_rounds - processed)};
        enif_consume_timeslice(env, 100);
        return enif_schedule_nif(env, "libdecaf_nif_parallel_absorb_continue", ERL_NIF_DIRTY_JOB_CPU_BOUND,
                                 libdecaf_nif_parallel_absorb_2, 2, arguments);
    }
    /* A reusable worker can keep helping other queues on its next bounded call.
     * Direct NIF callers do not receive worker-control messages. */
    ErlNifPid self, worker;
    ERL_NIF_TERM name = atomic_load_explicit(&libdecaf_nif_parallel_worker_names[router - 1], memory_order_acquire);
    if (enif_self(env, &self) != NULL && enif_whereis_pid(env, name, &worker) && enif_compare_pids(&self, &worker) == 0) {
        for (unsigned int i = 0; i < pool->count; i++) {
            if (atomic_load_explicit(&pool->queues[i].size, memory_order_acquire) != 0) {
                (void)enif_send(env, &self, NULL, ATOM(wakeup));
                break;
            }
        }
    }
    return ATOM(ok);
}
