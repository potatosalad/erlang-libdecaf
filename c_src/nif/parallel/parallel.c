#include "parallel.h"
#include "internal.h"
#include "leaf.h"
#include <decaf/common.h>

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
libdecaf_nif_parallel_pool_release(libdecaf_nif_parallel_pool_t *pool)
{
    if (atomic_fetch_sub_explicit(&pool->references, 1, memory_order_acq_rel) == 1) {
        decaf_bzero(pool, sizeof(*pool));
        enif_free(pool);
    }
}

int
libdecaf_nif_parallel_load(ErlNifEnv *env, void **priv_data, void *old_priv_data)
{
    if (old_priv_data != NULL) {
        libdecaf_nif_parallel_worker_atoms(env, ((libdecaf_nif_parallel_pool_t *)old_priv_data)->count);
        libdecaf_nif_parallel_pool_keep(old_priv_data);
        *priv_data = old_priv_data;
        return 0;
    }
    libdecaf_nif_parallel_pool_t *pool = enif_alloc(sizeof(*pool));
    if (pool == NULL)
        return -1;
    decaf_bzero(pool, sizeof(*pool));
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
            enif_free(pool);
            return -1;
        }
        pool->names[i] = enif_make_atom(env, name);
        atomic_init(&pool->queues[i].incoming, NULL);
        atomic_flag_clear(&pool->queues[i].reader);
        atomic_init(&pool->queues[i].cleanup, false);
        atomic_init(&pool->queues[i].size, 0);
    }
    *priv_data = pool;
    libdecaf_nif_parallel_worker_atoms(env, pool->count);
    return 0;
}

void
libdecaf_nif_parallel_unload(void *priv_data)
{
    if (priv_data != NULL)
        libdecaf_nif_parallel_pool_release(priv_data);
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
        atomic_fetch_sub_explicit(&queue->size, 1, memory_order_relaxed);
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
                    atomic_fetch_sub_explicit(&queue->size, 1, memory_order_relaxed);
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
libdecaf_nif_parallel_leaf_input(const libdecaf_nif_parallel_node_t *node)
{
    const libdecaf_nif_parallel_operation_t *operation = node->operation;
    return operation->input.data + operation->window_offset + node->index * operation->block_size;
}

static void
libdecaf_nif_parallel_leaf_complete(ErlNifEnv *env, libdecaf_nif_parallel_node_t *node)
{
    libdecaf_nif_parallel_operation_t *operation = node->operation;
    size_t index = node->index;
    if (!atomic_load_explicit(&operation->cancelled, memory_order_acquire)) {
        atomic_store_explicit(&operation->results[index].ready, true, memory_order_release);
    }
    if (atomic_fetch_add_explicit(&operation->completed, 1, memory_order_acq_rel) + 1 == operation->count) {
        if (!atomic_load_explicit(&operation->cancelled, memory_order_acquire)) {
            ERL_NIF_TERM reference = enif_make_copy(env, operation->reference);
            (void)enif_send(env, &operation->owner, NULL, enif_make_tuple2(env, ATOM(libdecaf_parallel), reference));
        }
        /* Publish after sending so the collector can flush the only notification
         * for this window without leaving a late message in its mailbox. */
        atomic_store_explicit(&operation->notified, true, memory_order_release);
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
        libdecaf_nif_parallel_node_t *nodes[16];
        size_t count = 0;
        while (count < 16 && (max_rounds == 0 || count < max_rounds - processed)) {
            libdecaf_nif_parallel_node_t *node = libdecaf_nif_parallel_queue_pop(queue);
            if (node == NULL)
                break;
            nodes[count++] = node;
        }
        /* Claimed nodes retain their operations independently. Release the queue
         * before hashing so idle workers can steal a short batch from it. */
        atomic_flag_clear_explicit(&queue->reader, memory_order_release);
        if (atomic_load(&queue->cleanup))
            libdecaf_nif_parallel_queue_cleanup(queue);
        if (count == 0)
            break;
        for (size_t i = 0; i < count; i++) {
            libdecaf_nif_parallel_node_t *node = nodes[i];
            libdecaf_nif_parallel_operation_t *operation = node->operation;
            bool cancelled = atomic_load_explicit(&operation->cancelled, memory_order_acquire);
            if (!cancelled && i + 1 < count && nodes[i + 1]->operation == operation) {
                libdecaf_nif_parallel_node_t *second = nodes[++i];
                libdecaf_nif_parallel_leaf_hash2(
                    operation->leaf, libdecaf_nif_parallel_leaf_input(node), libdecaf_nif_parallel_leaf_input(second),
                    operation->block_size, operation->results[node->index].chaining, operation->results[second->index].chaining);
                libdecaf_nif_parallel_leaf_complete(env, node);
                libdecaf_nif_parallel_leaf_complete(env, second);
            } else {
                if (!cancelled)
                    libdecaf_nif_parallel_leaf_hash(operation->leaf, libdecaf_nif_parallel_leaf_input(node), operation->block_size,
                                                    operation->results[node->index].chaining);
                libdecaf_nif_parallel_leaf_complete(env, node);
            }
        }
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
    libdecaf_nif_parallel_pool_t *pool = enif_priv_data(env);
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
    libdecaf_nif_parallel_pool_t *pool = enif_priv_data(env);
    unsigned int router;
    unsigned long max_rounds;
    if (argc != 2 || !enif_get_uint(env, argv[0], &router) || router == 0 || router > pool->count ||
        !enif_get_ulong(env, argv[1], &max_rounds))
        return EXCP_BADARG(env, "Expected a native parallel router number");
    size_t processed = 0, before;
    do {
        before = processed;
        for (unsigned int offset = 0; offset < pool->count && enif_is_current_process_alive(env); offset++) {
            if (max_rounds != 0 && processed == max_rounds)
                break;
            size_t budget = max_rounds == 0 ? 0 : max_rounds - processed;
            processed += libdecaf_nif_parallel_drain(env, pool, (router - 1 + offset) % pool->count, budget);
        }
    } while (max_rounds == 0 && processed != before);
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
