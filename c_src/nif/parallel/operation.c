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
                                       size_t block_size, bool finish, size_t output_length, ERL_NIF_TERM *error)
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
    if (capacity == 0)
        capacity = 1;
    size_t allocation = offsetof(libdecaf_nif_parallel_operation_t, results) + capacity * sizeof(libdecaf_nif_parallel_result_t);
    libdecaf_nif_parallel_operation_t *operation = enif_alloc_resource(type, allocation);
    if (operation == NULL) {
        *error = EXCP_ERROR(env, "Can't allocate parallel operation");
        enif_free_env(work_env);
        return NULL;
    }
    decaf_bzero(operation, allocation);
    atomic_init(&operation->cancelled, false);
    atomic_init(&operation->notified, false);
    atomic_init(&operation->completed, 0);
    for (size_t i = 0; i < capacity; i++) {
        atomic_init(&operation->results[i].ready, false);
        operation->results[i].node.operation = operation;
        operation->results[i].node.index = i;
    }
    operation->version = 1;
    operation->job_width = LIBDECAF_NIF_PARALLEL_JOB_LEAVES;
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
    decaf_bzero(heads, sizeof(heads));
    decaf_bzero(tails, sizeof(tails));
    decaf_bzero(counts, sizeof(counts));
    libdecaf_nif_parallel_pool_t *pool = operation->pool;
    size_t first = atomic_fetch_add_explicit(&pool->next_router, 1, memory_order_relaxed) % pool->count;
    /* Small fan-outs amortize worker wakeups and dirty scheduler transitions.
     * Assign contiguous leaves so workers do not share adjacent result lines. */
    size_t target_bytes = 128 * 1024;
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

int
libdecaf_nif_parallel_operation_step(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation, void *context,
                                     const libdecaf_nif_parallel_algorithm_t *algorithm)
{
    bool dispatched = false;
    bool normal = enif_thread_type() == ERL_NIF_THR_NORMAL_SCHEDULER;
    ErlNifTime started = normal ? enif_monotonic_time(ERL_NIF_USEC) : 0;
    size_t capacity = (enif_sizeof_resource(operation) - offsetof(libdecaf_nif_parallel_operation_t, results)) /
                      sizeof(libdecaf_nif_parallel_result_t);
    for (;;) {
        if (atomic_load_explicit(&operation->cancelled, memory_order_acquire))
            return -1;
        if (operation->count != 0) {
            while (operation->joined < operation->count &&
                   atomic_load_explicit(&operation->results[operation->joined].ready, memory_order_acquire)) {
                if (!algorithm->join(context, operation->results[operation->joined].chaining))
                    return -1;
                decaf_bzero(operation->results[operation->joined].chaining, 64);
                operation->joined++;
                if (normal && operation->joined % 128 == 0 && enif_monotonic_time(ERL_NIF_USEC) - started >= 100)
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
