#include "csprng.h"

#include <stdbool.h>
#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

enum {
    LIBDECAF_RANDOM_SEED_BYTES = 64,
    LIBDECAF_RANDOM_CACHE_BYTES = 4096,
    LIBDECAF_RANDOM_CHUNK_BYTES = 65536,
    LIBDECAF_RANDOM_RESEED_BYTES = 16 * 1024 * 1024,
    LIBDECAF_RANDOM_RESEED_SECONDS = 300
};

typedef struct {
    decaf_keccak_prng_s prng[2];
    uint8_t cache[LIBDECAF_RANDOM_CACHE_BYTES];
    size_t available, generated;
    ErlNifTime seeded_at;
    uint64_t process_id;
    bool seeded;
} libdecaf_nif_random_thread_t;

typedef struct {
    decaf_keccak_prng_s prng[2];
    ErlNifBinary output;
    size_t offset;
    bool owns_output;
} libdecaf_nif_random_trap_t;

static _Thread_local libdecaf_nif_random_thread_t libdecaf_nif_random_thread;
static ErlNifResourceType *libdecaf_nif_random_resource_type;

static ERL_NIF_TERM libdecaf_nif_random_seed_io(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_random_seed_ready(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_random_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

static void
libdecaf_nif_random_unload_thread(void *priv_data)
{
    (void)priv_data;
    decaf_bzero(&libdecaf_nif_random_thread, sizeof(libdecaf_nif_random_thread));
}

static void
libdecaf_nif_random_dtor(ErlNifEnv *env, void *object)
{
    (void)env;
    libdecaf_nif_random_trap_t *trap = object;
    if (trap->owns_output) {
        decaf_bzero(trap->output.data, trap->offset);
        enif_release_binary(&trap->output);
    }
    decaf_bzero(trap, sizeof(*trap));
}

int
libdecaf_nif_csprng_random_load(ErlNifEnv *env)
{
    libdecaf_nif_random_resource_type = enif_open_resource_type(env, "libdecaf_nif", "spongerng_random", libdecaf_nif_random_dtor,
                                                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    return libdecaf_nif_random_resource_type != NULL &&
                   enif_set_option(env, ERL_NIF_OPT_ON_UNLOAD_THREAD, libdecaf_nif_random_unload_thread) == 0
               ? 0
               : -1;
}

static uint64_t
libdecaf_nif_random_process_id(void)
{
#if defined(_WIN32)
    return (uint64_t)_getpid();
#else
    return (uint64_t)getpid();
#endif
}

static bool
libdecaf_nif_random_ready(void)
{
    libdecaf_nif_random_thread_t *thread = &libdecaf_nif_random_thread;
    return thread->seeded && thread->generated < LIBDECAF_RANDOM_RESEED_BYTES &&
           thread->process_id == libdecaf_nif_random_process_id() &&
           enif_monotonic_time(ERL_NIF_SEC) - thread->seeded_at < LIBDECAF_RANDOM_RESEED_SECONDS;
}

static void
libdecaf_nif_random_install(const uint8_t seed[LIBDECAF_RANDOM_SEED_BYTES])
{
    libdecaf_nif_random_thread_t *thread = &libdecaf_nif_random_thread;
    uint64_t process_id = libdecaf_nif_random_process_id();
    if (thread->seeded && thread->process_id == process_id) {
        for (size_t i = 0; i < 2; ++i)
            decaf_spongerng_stir(&thread->prng[i], seed, LIBDECAF_RANDOM_SEED_BYTES);
    } else {
        decaf_keccak_prng_s source;
        uint8_t derived[2 * LIBDECAF_RANDOM_SEED_BYTES];
        /* Derive independent seeds through the upstream construction. */
        decaf_spongerng_init_from_buffer(&source, seed, LIBDECAF_RANDOM_SEED_BYTES, 1);
        decaf_spongerng_next(&source, derived, sizeof(derived));
        for (size_t i = 0; i < 2; ++i)
            decaf_spongerng_init_from_buffer(&thread->prng[i], derived + i * LIBDECAF_RANDOM_SEED_BYTES, LIBDECAF_RANDOM_SEED_BYTES,
                                             1);
        decaf_spongerng_destroy(&source);
        decaf_bzero(derived, sizeof(derived));
    }
    decaf_bzero(thread->cache, sizeof(thread->cache));
    thread->available = 0;
    thread->generated = 0;
    thread->seeded_at = enif_monotonic_time(ERL_NIF_SEC);
    thread->process_id = process_id;
    thread->seeded = true;
}

static libdecaf_nif_random_trap_t *
libdecaf_nif_random_trap(ErlNifEnv *env, ERL_NIF_TERM term)
{
    libdecaf_nif_random_trap_t *trap;
    return enif_get_resource(env, term, libdecaf_nif_random_resource_type, (void **)&trap) ? trap : NULL;
}

static void
libdecaf_nif_random_cached(uint8_t *output, size_t length)
{
    libdecaf_nif_random_thread_t *thread = &libdecaf_nif_random_thread;
    while (length != 0) {
        if (thread->available == 0) {
            decaf_spongerng_next2(&thread->prng[0], &thread->prng[1], thread->cache, thread->cache + sizeof(thread->cache) / 2,
                                  sizeof(thread->cache) / 2);
            thread->available = sizeof(thread->cache);
        }
        size_t count = length < thread->available ? length : thread->available;
        uint8_t *source = thread->cache + sizeof(thread->cache) - thread->available;
        memcpy(output, source, count);
        decaf_bzero(source, count);
        thread->available -= count;
        output += count;
        length -= count;
    }
}

static void
libdecaf_nif_random_generate(decaf_keccak_prng_s state[2], uint8_t *output, size_t length)
{
    size_t half = length / 2;
    if (half != 0)
        decaf_spongerng_next2(&state[0], &state[1], output, output + half, half);
    if (length % 2 != 0)
        decaf_spongerng_next(&state[0], output + 2 * half, 1);
}

static ERL_NIF_TERM
libdecaf_nif_random_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_random_trap_t *trap = argc == 1 ? libdecaf_nif_random_trap(env, argv[0]) : NULL;
    if (trap == NULL || !enif_is_current_process_alive(env))
        return enif_make_badarg(env);
    size_t count = trap->output.size - trap->offset;
    if (count > LIBDECAF_RANDOM_CHUNK_BYTES)
        count = LIBDECAF_RANDOM_CHUNK_BYTES;
    libdecaf_nif_random_generate(trap->prng, trap->output.data + trap->offset, count);
    trap->offset += count;
    enif_consume_timeslice(env, (int)((count * 100 + LIBDECAF_RANDOM_CHUNK_BYTES - 1) / LIBDECAF_RANDOM_CHUNK_BYTES));
    if (trap->offset < trap->output.size)
        return enif_schedule_nif(env, "libdecaf_nif_random_continue", ERL_NIF_NORMAL_JOB_BOUND, libdecaf_nif_random_continue, 1,
                                 argv);
    trap->owns_output = false;
    decaf_bzero(trap->prng, sizeof(trap->prng));
    return enif_make_binary(env, &trap->output);
}

static ERL_NIF_TERM
libdecaf_nif_random_seed_io(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_random_trap_t *trap = argc == 2 ? libdecaf_nif_random_trap(env, argv[1]) : NULL;
    if (trap == NULL || !enif_is_current_process_alive(env))
        return enif_make_badarg(env);
    /* Upstream handles the platform's entropy source, including its Windows
     * equivalent. File I/O is confined to this dirty I/O continuation. */
    if (decaf_spongerng_init_from_file(&trap->prng[0], "/dev/urandom", LIBDECAF_RANDOM_SEED_BYTES, 1) != DECAF_SUCCESS)
        return ATOM(need_seed);
    return enif_schedule_nif(env, "libdecaf_nif_random_seed_ready", ERL_NIF_NORMAL_JOB_BOUND, libdecaf_nif_random_seed_ready, 2,
                             argv);
}

static ERL_NIF_TERM
libdecaf_nif_random_seed_ready(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_random_trap_t *trap = argc == 2 ? libdecaf_nif_random_trap(env, argv[1]) : NULL;
    if (trap == NULL || !enif_is_current_process_alive(env))
        return enif_make_badarg(env);
    uint8_t seed[LIBDECAF_RANDOM_SEED_BYTES];
    decaf_spongerng_next(&trap->prng[0], seed, sizeof(seed));
    /* Install on the normal scheduler that actually resumes the caller, which
     * need not be the scheduler that originally requested entropy. */
    libdecaf_nif_random_install(seed);
    decaf_bzero(seed, sizeof(seed));
    decaf_bzero(trap->prng, sizeof(trap->prng));
    return libdecaf_nif_strong_rand_bytes_1(env, 1, argv);
}

ERL_NIF_TERM
libdecaf_nif_strong_rand_bytes_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    unsigned long length;
    if (argc != 1 || !enif_get_ulong(env, argv[0], &length))
        return EXCP_BADARG(env, "Expected a non-negative random byte length");
    if (length == 0) {
        ERL_NIF_TERM result;
        (void)enif_make_new_binary(env, 0, &result);
        return result;
    }
    if (!libdecaf_nif_random_ready()) {
        libdecaf_nif_random_trap_t *seed = enif_alloc_resource(libdecaf_nif_random_resource_type, sizeof(*seed));
        if (seed == NULL)
            return EXCP_ERROR(env, "Cannot allocate SpongeRNG seed state");
        decaf_bzero(seed, sizeof(*seed));
        ERL_NIF_TERM arguments[] = {argv[0], enif_make_resource(env, seed)};
        enif_release_resource(seed);
        return enif_schedule_nif(env, "libdecaf_nif_random_seed_io", ERL_NIF_DIRTY_JOB_IO_BOUND, libdecaf_nif_random_seed_io, 2,
                                 arguments);
    }
    libdecaf_nif_random_thread_t *thread = &libdecaf_nif_random_thread;
    if (length <= LIBDECAF_RANDOM_CACHE_BYTES) {
        ERL_NIF_TERM result;
        uint8_t *output = enif_make_new_binary(env, length, &result);
        if (output == NULL)
            return EXCP_ERROR(env, "Cannot allocate random bytes");
        if (length <= 256)
            libdecaf_nif_random_cached(output, length);
        else
            libdecaf_nif_random_generate(thread->prng, output, length);
        thread->generated += length;
        return result;
    }
    libdecaf_nif_random_trap_t *trap = enif_alloc_resource(libdecaf_nif_random_resource_type, sizeof(*trap));
    if (trap == NULL)
        return EXCP_ERROR(env, "Cannot allocate SpongeRNG output state");
    decaf_bzero(trap, sizeof(*trap));
    if (!enif_alloc_binary(length, &trap->output)) {
        enif_release_resource(trap);
        return EXCP_ERROR(env, "Cannot allocate random bytes");
    }
    trap->owns_output = true;
    uint8_t seed[2 * LIBDECAF_RANDOM_SEED_BYTES];
    /* Ratchet the thread's generator and give this request an independent PRNG,
     * so yielding and scheduler migration cannot expose or reuse cached state. */
    libdecaf_nif_random_cached(seed, sizeof(seed));
    for (size_t i = 0; i < 2; ++i)
        decaf_spongerng_init_from_buffer(&trap->prng[i], seed + i * LIBDECAF_RANDOM_SEED_BYTES, LIBDECAF_RANDOM_SEED_BYTES, 1);
    decaf_bzero(seed, sizeof(seed));
    size_t remaining = LIBDECAF_RANDOM_RESEED_BYTES - thread->generated;
    thread->generated += length < remaining ? length : remaining;
    ERL_NIF_TERM argument = enif_make_resource(env, trap);
    enif_release_resource(trap);
    return libdecaf_nif_random_continue(env, 1, &argument);
}

ERL_NIF_TERM
libdecaf_nif_strong_rand_bytes_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary seed;
    unsigned long length;
    if (argc != 2 || !enif_get_ulong(env, argv[0], &length) || !enif_inspect_binary(env, argv[1], &seed) ||
        seed.size != LIBDECAF_RANDOM_SEED_BYTES)
        return EXCP_BADARG(env, "Expected a length and 64 cryptographically random seed bytes");
    libdecaf_nif_random_install(seed.data);
    return libdecaf_nif_strong_rand_bytes_1(env, 1, argv);
}
