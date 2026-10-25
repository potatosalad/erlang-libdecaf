#include "internal.h"
#include <decaf/common.h>

static void
libdecaf_nif_parallel_operation_dtor(ErlNifEnv *env, void *object)
{
    (void)env;
    libdecaf_nif_parallel_operation_t *operation = object;
    if (operation->work_env != NULL)
        enif_free_env(operation->work_env);
    if (operation->pool != NULL)
        libdecaf_nif_parallel_pool_release(operation->pool, operation->version != 0);
    decaf_bzero(operation, enif_sizeof_resource(operation));
}

static void
libdecaf_nif_parallel_operation_down(ErlNifEnv *env, void *object, ErlNifPid *pid, ErlNifMonitor *monitor)
{
    (void)env;
    (void)pid;
    (void)monitor;
    libdecaf_nif_parallel_operation_t *operation = object;
    atomic_store_explicit(&operation->cancelled, true, memory_order_release);
    for (unsigned int i = 0; i < operation->pool->count; i++)
        libdecaf_nif_parallel_queue_cleanup(&operation->pool->queues[i]);
}

ErlNifResourceType *
libdecaf_nif_parallel_operation_load(ErlNifEnv *env, const char *name)
{
    ErlNifResourceTypeInit init = {
        .dtor = libdecaf_nif_parallel_operation_dtor, .down = libdecaf_nif_parallel_operation_down, .members = 3};
    return enif_open_resource_type_x(env, name, &init, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
}

libdecaf_nif_parallel_operation_t *
libdecaf_nif_parallel_operation_create(ErlNifEnv *env, ErlNifResourceType *type, ERL_NIF_TERM state, ERL_NIF_TERM input,
                                       size_t block_size, libdecaf_nif_parallel_leaf_t leaf, bool finish, size_t output_length,
                                       ERL_NIF_TERM *error)
{
    ErlNifEnv *work_env = enif_alloc_env();
    if (work_env == NULL) {
        *error = EXCP_ERROR(env, "Can't allocate parallel input environment");
        return NULL;
    }
    ERL_NIF_TERM retained_state = enif_make_copy(work_env, state);
    ERL_NIF_TERM retained_input = enif_make_copy(work_env, input);
    ErlNifBinary binary;
    /* Ref-counted binary payloads are retained once. Iodata is flattened once;
     * chunks themselves contain only offsets into this retained input. */
    if (block_size == 0 || !enif_inspect_iolist_as_binary(work_env, retained_input, &binary)) {
        *error = EXCP_BADARG(env, "Expected input bytes or iodata");
        enif_free_env(work_env);
        return NULL;
    }
    size_t capacity = binary.size / block_size;
    if (capacity > LIBDECAF_NIF_PARALLEL_WINDOW)
        capacity = LIBDECAF_NIF_PARALLEL_WINDOW;
    size_t width = LIBDECAF_NIF_PARALLEL_JOB_LEAVES;
    capacity = capacity == 0 ? width : (capacity + width - 1) / width * width;
    size_t jobs = capacity / width * LIBDECAF_NIF_PARALLEL_WINDOWS;
    size_t chaining_length = 200 - leaf.rate;
    size_t allocation = offsetof(libdecaf_nif_parallel_operation_t, results) + offsetof(libdecaf_nif_parallel_pipeline_t, jobs) +
                        jobs * sizeof(libdecaf_nif_parallel_job_t) + capacity * LIBDECAF_NIF_PARALLEL_WINDOWS * chaining_length;
    libdecaf_nif_parallel_operation_t *operation = enif_alloc_resource(type, allocation);
    if (operation == NULL) {
        *error = EXCP_ERROR(env, "Can't allocate parallel operation");
        enif_free_env(work_env);
        return NULL;
    }
    /* Chaining values are unreadable until their job's ready bits are published.
     * Only metadata needs initialization; workers fully overwrite the output. */
    decaf_bzero(operation, offsetof(libdecaf_nif_parallel_operation_t, results));
    atomic_init(&operation->cancelled, false);
    atomic_init(&operation->notified, false);
    atomic_init(&operation->completed, 0);
    libdecaf_nif_parallel_pipeline_t *pipeline = libdecaf_nif_parallel_pipeline(operation);
    decaf_bzero(pipeline, offsetof(libdecaf_nif_parallel_pipeline_t, jobs));
    pipeline->capacity = capacity;
    pipeline->chaining_length = chaining_length;
    for (size_t i = 0; i < LIBDECAF_NIF_PARALLEL_WINDOWS; i++) {
        atomic_init(&pipeline->windows[i].completed, 0);
        atomic_init(&pipeline->windows[i].notified, false);
    }
    for (size_t i = 0; i < jobs; i++) {
        atomic_init(&pipeline->jobs[i].ready, 0);
        pipeline->jobs[i].node.next = NULL;
        pipeline->jobs[i].node.operation = operation;
        pipeline->jobs[i].node.index = i * width;
    }
    operation->version = 2;
    operation->job_width = LIBDECAF_NIF_PARALLEL_JOB_LEAVES;
    operation->block_size = block_size;
    operation->leaf = leaf;
    operation->pool = libdecaf_nif_parallel_pool_current(env);
    libdecaf_nif_parallel_pool_keep(operation->pool);
    operation->work_env = work_env;
    operation->state = retained_state;
    operation->input = binary;
    operation->reference = enif_make_copy(operation->work_env, enif_make_ref(env));
    operation->finish = finish;
    operation->output_length = output_length;
    if (enif_self(env, &operation->owner) == NULL ||
        enif_monitor_process(env, operation, &operation->owner, &operation->monitor) != 0) {
        *error = EXCP_ERROR(env, "Can't monitor parallel operation owner");
        enif_release_resource(operation);
        return NULL;
    }
    operation->monitored = true;
    return operation;
}

libdecaf_nif_parallel_operation_t *
libdecaf_nif_parallel_operation_get(ErlNifEnv *env, ErlNifResourceType *type, ERL_NIF_TERM term)
{
    libdecaf_nif_parallel_operation_t *operation;
    ErlNifPid caller;
    if (!enif_get_resource(env, term, type, (void **)&operation) || enif_self(env, &caller) == NULL ||
        enif_compare_pids(&caller, &operation->owner) != 0 || operation->finished || atomic_load(&operation->cancelled))
        return NULL;
    return operation;
}

ERL_NIF_TERM
libdecaf_nif_parallel_operation_state(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation)
{
    return enif_make_copy(env, operation->state);
}

void
libdecaf_nif_parallel_operation_abort(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation)
{
    atomic_store_explicit(&operation->cancelled, true, memory_order_release);
    if (operation->monitored) {
        (void)enif_demonitor_process(env, operation, &operation->monitor);
        operation->monitored = false;
    }
    for (unsigned int i = 0; i < operation->pool->count; i++)
        libdecaf_nif_parallel_queue_cleanup(&operation->pool->queues[i]);
}

ERL_NIF_TERM
libdecaf_nif_parallel_operation_result(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation, ERL_NIF_TERM state)
{
    ERL_NIF_TERM reference = enif_make_copy(env, operation->reference);
    if (operation->finish)
        return enif_make_tuple4(env, ATOM(finalize), reference, state, enif_make_ulong(env, operation->output_length));
    return enif_make_tuple3(env, ATOM(done), reference, state);
}

static bool
libdecaf_nif_parallel_dispatch(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation)
{
    bool fallback = false;
    libdecaf_nif_parallel_node_t *heads[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];
    libdecaf_nif_parallel_node_t *tails[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];
    size_t counts[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];
    libdecaf_nif_parallel_pool_t *pool = operation->pool;
    decaf_bzero(heads, pool->count * sizeof(heads[0]));
    decaf_bzero(tails, pool->count * sizeof(tails[0]));
    decaf_bzero(counts, pool->count * sizeof(counts[0]));
    size_t first = atomic_fetch_add_explicit(&pool->next_router, 1, memory_order_relaxed) % pool->count;
    /* Small fan-outs amortize worker wakeups and dirty scheduler transitions.
     * Assign contiguous leaves so workers do not share adjacent result lines. */
    /* Fast KT kernels amortize fewer wakeups on larger updates. Small updates
     * still need enough simultaneous workers to keep their latency down. */
    size_t input_bytes = operation->count * operation->block_size;
    size_t target_bytes = operation->leaf.turbo && input_bytes >= 2 * 1024 * 1024 ? 512 * 1024 : 128 * 1024;
    size_t workers = 1 + (operation->count * operation->block_size - 1) / target_bytes;
    if (workers > pool->count)
        workers = pool->count;
    size_t width = operation->job_width != 0 ? operation->job_width : 1;
    size_t jobs = (operation->count + width - 1) / width;
    if (workers > jobs)
        workers = jobs;
    bool help = workers > 1 && enif_thread_type() == ERL_NIF_THR_DIRTY_CPU_SCHEDULER;
    unsigned int helper = (unsigned int)((first + workers - 1) % pool->count);
    atomic_store_explicit(&operation->notified, false, memory_order_relaxed);
    for (size_t i = 0; i < operation->count; i++)
        atomic_store_explicit(&operation->results[i].ready, false, memory_order_relaxed);
    for (size_t i = 0; i < operation->count; i += width) {
        size_t batch = (i / width) * workers / jobs;
        unsigned int router = (unsigned int)((first + batch) % pool->count);
        libdecaf_nif_parallel_node_t *node = &operation->results[i].node;
        node->next = NULL;
        if (tails[router] == NULL)
            heads[router] = node;
        else
            tails[router]->next = node;
        tails[router] = node;
        counts[router] += libdecaf_nif_parallel_job_size(node);
        enif_keep_resource(operation);
    }
    for (unsigned int i = 0; i < pool->count; i++) {
        if (heads[i] != NULL) {
            libdecaf_nif_parallel_queue_push(&pool->queues[i], heads[i], tails[i], counts[i]);
            if (help && i == helper)
                continue;
            if (!libdecaf_nif_parallel_wakeup(env, pool, i)) {
                if (enif_thread_type() == ERL_NIF_THR_NORMAL_SCHEDULER)
                    fallback = true;
                else
                    libdecaf_nif_parallel_drain(env, pool, i, LIBDECAF_NIF_PARALLEL_WINDOW);
            }
        }
    }
    /* The caller already occupies a dirty CPU scheduler. Give it one share of
     * the leaf work instead of parking it while a replacement worker starts. */
    if (help)
        libdecaf_nif_parallel_drain(env, pool, helper, counts[helper]);
    if (atomic_load_explicit(&operation->cancelled, memory_order_acquire)) {
        for (unsigned int i = 0; i < pool->count; i++)
            libdecaf_nif_parallel_queue_cleanup(&pool->queues[i]);
    }
    return fallback;
}

static unsigned int
libdecaf_nif_parallel_window_dispatch(libdecaf_nif_parallel_operation_t *operation, unsigned int slot)
{
    libdecaf_nif_parallel_pipeline_t *pipeline = libdecaf_nif_parallel_pipeline(operation);
    libdecaf_nif_parallel_window_t *window = &pipeline->windows[slot];
    libdecaf_nif_parallel_pool_t *pool = operation->pool;
    libdecaf_nif_parallel_node_t *heads[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];
    libdecaf_nif_parallel_node_t *tails[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];
    size_t counts[LIBDECAF_NIF_PARALLEL_ROUTER_LIMIT];
    decaf_bzero(heads, pool->count * sizeof(heads[0]));
    decaf_bzero(tails, pool->count * sizeof(tails[0]));
    decaf_bzero(counts, pool->count * sizeof(counts[0]));
    size_t first = atomic_fetch_add_explicit(&pool->next_router, 1, memory_order_relaxed) % pool->count;
    size_t input_bytes = window->count * operation->block_size;
    size_t target_bytes = operation->leaf.turbo && input_bytes >= 2 * 1024 * 1024 ? 512 * 1024 : 128 * 1024;
    size_t workers = 1 + (input_bytes - 1) / target_bytes;
    if (workers > pool->count)
        workers = pool->count;
    const size_t width = LIBDECAF_NIF_PARALLEL_JOB_LEAVES;
    size_t jobs = (window->count + width - 1) / width;
    if (workers > jobs)
        workers = jobs;
    for (size_t i = 0; i < window->count; i += width) {
        size_t index = slot * pipeline->capacity + i;
        libdecaf_nif_parallel_job_t *job = libdecaf_nif_parallel_job(operation, index);
        atomic_store_explicit(&job->ready, 0, memory_order_relaxed);
        job->node.index = index;
        job->node.next = NULL;
        size_t router = (first + (i / width) * workers / jobs) % pool->count;
        if (tails[router] == NULL)
            heads[router] = &job->node;
        else
            tails[router]->next = &job->node;
        tails[router] = &job->node;
        counts[router] += libdecaf_nif_parallel_job_size(&job->node);
        enif_keep_resource(operation);
    }
    for (unsigned int i = 0; i < pool->count; i++) {
        if (heads[i] != NULL) {
            libdecaf_nif_parallel_queue_push(&pool->queues[i], heads[i], tails[i], counts[i]);
        }
    }
    return (unsigned int)first;
}

static int
libdecaf_nif_parallel_pipeline_step(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation, void *context,
                                    const libdecaf_nif_parallel_algorithm_t *algorithm)
{
    libdecaf_nif_parallel_pipeline_t *pipeline = libdecaf_nif_parallel_pipeline(operation);
    bool normal = enif_thread_type() == ERL_NIF_THR_NORMAL_SCHEDULER;
    ErlNifTime started = normal ? enif_monotonic_time(ERL_NIF_USEC) : 0;
    for (;;) {
        if (atomic_load_explicit(&operation->cancelled, memory_order_acquire))
            return -1;
        bool active = false;
        for (size_t i = 0; i < LIBDECAF_NIF_PARALLEL_WINDOWS; i++)
            active |= pipeline->windows[i].active;
        if (!active) {
            size_t remaining = operation->input.size - operation->offset;
            if (remaining == 0) {
                operation->finished = true;
                if (operation->monitored) {
                    (void)enif_demonitor_process(env, operation, &operation->monitor);
                    operation->monitored = false;
                }
                return 1;
            }
            size_t prefix = algorithm->prefix(context);
            if (prefix != 0 || remaining < operation->block_size) {
                size_t take = prefix != 0 && prefix < remaining ? prefix : remaining;
                algorithm->update(context, operation->input.data + operation->offset, take);
                operation->offset += take;
                continue;
            }
        }
        /* Refill the free slot before joining the current one. Workers can
         * hash ahead, but only the owner mutates the root, in input order. */
        bool dispatched = false;
        unsigned int helper = 0;
        for (unsigned int i = 0; i < LIBDECAF_NIF_PARALLEL_WINDOWS; i++) {
            unsigned int slot = (pipeline->current + i) % LIBDECAF_NIF_PARALLEL_WINDOWS;
            libdecaf_nif_parallel_window_t *window = &pipeline->windows[slot];
            size_t count = (operation->input.size - operation->offset) / operation->block_size;
            if (window->active || count == 0)
                continue;
            if (normal)
                return 3;
            if (count > pipeline->capacity)
                count = pipeline->capacity;
            window->offset = operation->offset;
            window->count = count;
            window->joined = 0;
            window->active = true;
            atomic_store_explicit(&window->completed, 0, memory_order_relaxed);
            atomic_store_explicit(&window->notified, false, memory_order_relaxed);
            operation->offset += count * operation->block_size;
            helper = libdecaf_nif_parallel_window_dispatch(operation, slot);
            dispatched = true;
        }
        /* Publish both windows before the calling dirty scheduler helps with
         * a bounded share. It need not sit idle while workers start running. */
        if (dispatched) {
            for (unsigned int i = 0; i < operation->pool->count; i++) {
                if (!libdecaf_nif_parallel_wakeup(env, operation->pool, i))
                    libdecaf_nif_parallel_drain(env, operation->pool, i, LIBDECAF_NIF_PARALLEL_WINDOW);
            }
            libdecaf_nif_parallel_drain(env, operation->pool, helper, 128);
        }
        libdecaf_nif_parallel_window_t *window = &pipeline->windows[pipeline->current];
        while (window->joined < window->count) {
            size_t count = 0;
            while (count < 128 && window->joined + count < window->count) {
                size_t available = window->count - window->joined - count;
                size_t take = available < LIBDECAF_NIF_PARALLEL_JOB_LEAVES ? available : LIBDECAF_NIF_PARALLEL_JOB_LEAVES;
                size_t index = pipeline->current * pipeline->capacity + window->joined + count;
                unsigned int mask = (1u << take) - 1u;
                if ((atomic_load_explicit(&libdecaf_nif_parallel_job(operation, index)->ready, memory_order_acquire) & mask) !=
                    mask)
                    break;
                count += take;
            }
            if (count == 0)
                break;
            uint8_t *chaining = libdecaf_nif_parallel_chaining(operation, pipeline->current * pipeline->capacity + window->joined);
            bool valid = algorithm->join(context, chaining, count);
            decaf_bzero(chaining, count * pipeline->chaining_length);
            if (!valid)
                return -1;
            window->joined += count;
            if (normal && enif_monotonic_time(ERL_NIF_USEC) - started >= 100)
                return 2;
        }
        if (window->joined == window->count && atomic_load_explicit(&window->notified, memory_order_acquire)) {
            window->active = false;
            pipeline->current = (pipeline->current + 1) % LIBDECAF_NIF_PARALLEL_WINDOWS;
            continue;
        }
        if (atomic_load_explicit(&window->completed, memory_order_acquire) == window->count)
            return 2;
        if (dispatched)
            return 0;
        /* Recheck missing/restarted workers on each continuation. Retired pools
         * from an older NIF are drained by the owner on a dirty scheduler. */
        for (unsigned int i = 0; i < operation->pool->count; i++) {
            if (!libdecaf_nif_parallel_wakeup(env, operation->pool, i)) {
                if (normal)
                    return 3;
                libdecaf_nif_parallel_drain(env, operation->pool, i, LIBDECAF_NIF_PARALLEL_WINDOW);
            }
        }
        if (atomic_load_explicit(&window->completed, memory_order_acquire) == window->count)
            continue;
        return 0;
    }
}

int
libdecaf_nif_parallel_operation_step(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation, void *context,
                                     const libdecaf_nif_parallel_algorithm_t *algorithm)
{
    if (operation->version >= 2)
        return libdecaf_nif_parallel_pipeline_step(env, operation, context, algorithm);
    /* Keep in-flight version 0/1 resources readable during NIF takeover. */
    bool dispatched = false;
    bool normal = enif_thread_type() == ERL_NIF_THR_NORMAL_SCHEDULER;
    ErlNifTime started = normal ? enif_monotonic_time(ERL_NIF_USEC) : 0;
    size_t capacity = (enif_sizeof_resource(operation) - offsetof(libdecaf_nif_parallel_operation_t, results)) /
                      sizeof(libdecaf_nif_parallel_result_t);
    for (;;) {
        if (atomic_load_explicit(&operation->cancelled, memory_order_acquire))
            return -1;
        if (operation->count != 0) {
            /* Join a contiguous run in one sponge update so the root can use
             * its register-resident absorb loop, rather than crossing vtables
             * and copying sponge state for every 32/64-byte chaining value. */
            const size_t chaining_length = 200 - operation->leaf.rate;
            uint8_t chaining[128 * 64];
            while (operation->joined < operation->count) {
                size_t count = 0;
                while (count < 128 && operation->joined + count < operation->count &&
                       atomic_load_explicit(&operation->results[operation->joined + count].ready, memory_order_acquire)) {
                    memcpy(chaining + count * chaining_length, operation->results[operation->joined + count].chaining,
                           chaining_length);
                    decaf_bzero(operation->results[operation->joined + count].chaining, 64);
                    ++count;
                }
                if (count == 0)
                    break;
                bool valid = algorithm->join(context, chaining, count);
                decaf_bzero(chaining, count * chaining_length);
                if (!valid)
                    return -1;
                operation->joined += count;
                if (normal && enif_monotonic_time(ERL_NIF_USEC) - started >= 100)
                    return 2;
            }
            if (operation->joined != operation->count || !atomic_load_explicit(&operation->notified, memory_order_acquire)) {
                if (operation->joined == operation->count &&
                    atomic_load_explicit(&operation->completed, memory_order_acquire) == operation->count)
                    return 2;
                if (dispatched)
                    return 0;
                size_t completed = atomic_load_explicit(&operation->completed, memory_order_acquire);
                for (unsigned int i = 0; i < operation->pool->count; i++) {
                    if (!libdecaf_nif_parallel_wakeup(env, operation->pool, i)) {
                        if (normal)
                            return 3;
                        libdecaf_nif_parallel_drain(env, operation->pool, i, LIBDECAF_NIF_PARALLEL_WINDOW);
                    }
                }
                if (atomic_load_explicit(&operation->completed, memory_order_acquire) != completed)
                    continue;
                return 0;
            }
            operation->count = operation->joined = 0;
            atomic_store_explicit(&operation->completed, 0, memory_order_relaxed);
        }
        if (operation->offset == operation->input.size) {
            operation->finished = true;
            if (operation->monitored) {
                (void)enif_demonitor_process(env, operation, &operation->monitor);
                operation->monitored = false;
            }
            return 1;
        }
        size_t remaining = operation->input.size - operation->offset;
        size_t prefix = algorithm->prefix(context);
        size_t block_size = algorithm->block_size(context);
        if (block_size == 0)
            return -1;
        if (prefix != 0 || remaining < block_size) {
            size_t take = prefix != 0 && prefix < remaining ? prefix : remaining;
            algorithm->update(context, operation->input.data + operation->offset, take);
            operation->offset += take;
            continue;
        }
        if (normal)
            return 3;
        operation->block_size = block_size;
        operation->leaf = algorithm->leaf(context);
        operation->window_offset = operation->offset;
        operation->count = remaining / block_size;
        if (operation->count > capacity)
            operation->count = capacity;
        operation->offset += operation->count * block_size;
        if (libdecaf_nif_parallel_dispatch(env, operation))
            return 3;
        dispatched = true;
    }
}

ERL_NIF_TERM
libdecaf_nif_parallel_operation_await(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation)
{
    return enif_make_tuple3(env, ATOM(await), enif_make_copy(env, operation->reference), enif_make_resource(env, operation));
}
