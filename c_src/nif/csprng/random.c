#include "csprng.h"

#include <stdbool.h>
#include <stdatomic.h>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#elif !defined(_WIN32) && !defined(__APPLE__) && !defined(__OpenBSD__)
#include <fcntl.h>
#endif

enum {
    LIBDECAF_RANDOM_SEED_BYTES = 64,
    LIBDECAF_RANDOM_CHUNK_BYTES = 65536,
    LIBDECAF_RANDOM_RESEED_BYTES = 16 * 1024 * 1024,
    LIBDECAF_RANDOM_RESEED_SECONDS = 300
};

typedef struct libdecaf_nif_random_state_s libdecaf_nif_random_state_t;
struct libdecaf_nif_random_state_s {
    decaf_keccak_prng_s prng;
    libdecaf_nif_random_state_t *next;
    ErlNifTime seeded_at;
    uint64_t process_id;
    size_t generated;
    bool seeded;
};

/* enif_tsd_set() cannot retain values on emulator threads between callbacks.
 * Use native TLS instead, and own the allocations until the library unloads.
 * The list is touched only when a thread first calls us or during unloading. */
static _Thread_local libdecaf_nif_random_state_t *libdecaf_nif_random_thread_state;
static _Thread_local uint64_t libdecaf_nif_random_thread_generation;
static libdecaf_nif_random_state_t *libdecaf_nif_random_states;
static uint64_t libdecaf_nif_random_generation;
static size_t libdecaf_nif_random_load_count;
static atomic_flag libdecaf_nif_random_lock = ATOMIC_FLAG_INIT;

static void
libdecaf_nif_random_lock_acquire(void)
{
    while (atomic_flag_test_and_set_explicit(&libdecaf_nif_random_lock, memory_order_acquire)) {
    }
}

static void
libdecaf_nif_random_lock_release(void)
{
    atomic_flag_clear_explicit(&libdecaf_nif_random_lock, memory_order_release);
}

void
libdecaf_nif_csprng_random_load(void)
{
    libdecaf_nif_random_lock_acquire();
    /* Multiple module versions can share the same loaded native library. */
    if (libdecaf_nif_random_load_count++ == 0) {
        libdecaf_nif_random_generation++;
    }
    libdecaf_nif_random_lock_release();
}

void
libdecaf_nif_csprng_random_unload(void)
{
    libdecaf_nif_random_lock_acquire();
    if (--libdecaf_nif_random_load_count == 0) {
        /* The last module version has no executing NIFs at this point. */
        while (libdecaf_nif_random_states != NULL) {
            libdecaf_nif_random_state_t *state = libdecaf_nif_random_states;
            libdecaf_nif_random_states = state->next;
            decaf_bzero(state, sizeof(*state));
            enif_free(state);
        }
    }
    libdecaf_nif_random_lock_release();
}

static libdecaf_nif_random_state_t *
libdecaf_nif_random_state(void)
{
    if (libdecaf_nif_random_thread_generation != libdecaf_nif_random_generation) {
        libdecaf_nif_random_state_t *state = enif_alloc(sizeof(*state));
        if (state == NULL) {
            return NULL;
        }
        decaf_bzero(state, sizeof(*state));
        libdecaf_nif_random_lock_acquire();
        state->next = libdecaf_nif_random_states;
        libdecaf_nif_random_states = state;
        libdecaf_nif_random_lock_release();
        libdecaf_nif_random_thread_state = state;
        libdecaf_nif_random_thread_generation = libdecaf_nif_random_generation;
    }
    return libdecaf_nif_random_thread_state;
}

static bool
libdecaf_nif_random_os_seed(uint8_t seed[LIBDECAF_RANDOM_SEED_BYTES])
{
#if defined(__linux__)
    size_t offset = 0;
    while (offset < LIBDECAF_RANDOM_SEED_BYTES) {
        /* Do not block a dirty CPU thread waiting for early-boot entropy. */
        ssize_t count = getrandom(seed + offset, LIBDECAF_RANDOM_SEED_BYTES - offset, GRND_NONBLOCK);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        offset += (size_t)count;
    }
    return true;
#elif defined(__APPLE__) || defined(__OpenBSD__)
    return getentropy(seed, LIBDECAF_RANDOM_SEED_BYTES) == 0;
#elif defined(_WIN32)
    /* crypto:strong_rand_bytes/1 supplies the seed on this platform. */
    (void)seed;
    return false;
#else
    int fd;
    do {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return false;
    }
    size_t offset = 0;
    while (offset < LIBDECAF_RANDOM_SEED_BYTES) {
        ssize_t count = read(fd, seed + offset, LIBDECAF_RANDOM_SEED_BYTES - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            close(fd);
            return false;
        }
        offset += (size_t)count;
    }
    close(fd);
    return true;
#endif
}

static bool
libdecaf_nif_random_seed(libdecaf_nif_random_state_t *state, const ErlNifBinary *fallback)
{
#if defined(_WIN32)
    uint64_t process_id = (uint64_t)_getpid();
#else
    uint64_t process_id = (uint64_t)getpid();
#endif
    ErlNifTime now = enif_monotonic_time(ERL_NIF_SEC);
    if (state->seeded && state->process_id != process_id) {
        decaf_spongerng_destroy(&state->prng);
        state->seeded = false;
    }
    if (fallback == NULL && state->seeded && state->generated < LIBDECAF_RANDOM_RESEED_BYTES &&
        now - state->seeded_at < LIBDECAF_RANDOM_RESEED_SECONDS) {
        return true;
    }

    uint8_t seed[LIBDECAF_RANDOM_SEED_BYTES];
    if (fallback != NULL) {
        memcpy(seed, fallback->data, sizeof(seed));
    } else if (!libdecaf_nif_random_os_seed(seed)) {
        decaf_bzero(seed, sizeof(seed));
        return false;
    }
    if (state->seeded) {
        decaf_spongerng_stir(&state->prng, seed, sizeof(seed));
    } else {
        /* OS entropy supplies unpredictability. Disable the optional upstream
         * CPU-entropy path, whose x86 feature-detection globals are not atomic. */
        decaf_spongerng_init_from_buffer(&state->prng, seed, sizeof(seed), 1);
    }
    decaf_bzero(seed, sizeof(seed));
    state->seeded = true;
    state->process_id = process_id;
    state->seeded_at = now;
    state->generated = 0;
    return true;
}

static ERL_NIF_TERM
libdecaf_nif_random_bytes(ErlNifEnv *env, ERL_NIF_TERM length_term, const ErlNifBinary *fallback)
{
    unsigned long length;
    if (!enif_get_ulong(env, length_term, &length)) {
        return EXCP_BADARG(env, "Bad argument: 'Length'");
    }
    if (length == 0) {
        ERL_NIF_TERM empty;
        (void)enif_make_new_binary(env, 0, &empty);
        return empty;
    }
    libdecaf_nif_random_state_t *state = libdecaf_nif_random_state();
    if (state == NULL) {
        return EXCP_ERROR(env, "Can't allocate thread-local SpongeRNG state");
    }
    if (!libdecaf_nif_random_seed(state, fallback)) {
        return ATOM(need_seed);
    }
    ErlNifBinary output;
    if (!enif_alloc_binary(length, &output)) {
        return EXCP_ERROR(env, "Can't allocate random bytes");
    }
    size_t offset = 0;
    while (offset < output.size) {
        if (!enif_is_current_process_alive(env)) {
            decaf_bzero(output.data, offset);
            enif_release_binary(&output);
            return EXCP_ERROR(env, "Random byte generation cancelled");
        }
        size_t count = output.size - offset;
        if (count > LIBDECAF_RANDOM_CHUNK_BYTES) {
            count = LIBDECAF_RANDOM_CHUNK_BYTES;
        }
        decaf_spongerng_next(&state->prng, output.data + offset, count);
        offset += count;
        if (state->generated < LIBDECAF_RANDOM_RESEED_BYTES) {
            size_t remaining = LIBDECAF_RANDOM_RESEED_BYTES - state->generated;
            state->generated += count < remaining ? count : remaining;
        }
    }
    return enif_make_binary(env, &output);
}

ERL_NIF_TERM
libdecaf_nif_spongerng_random_bytes_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return EXCP_NOTSUP(env, "argc must be 1");
    }
    return libdecaf_nif_random_bytes(env, argv[0], NULL);
}

ERL_NIF_TERM
libdecaf_nif_spongerng_random_bytes_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary seed;
    if (argc != 2) {
        return EXCP_NOTSUP(env, "argc must be 2");
    }
    if (!enif_inspect_binary(env, argv[1], &seed) || seed.size != LIBDECAF_RANDOM_SEED_BYTES) {
        return EXCP_BADARG(env, "Bad argument: 'Seed' must contain 64 cryptographically random bytes");
    }
    return libdecaf_nif_random_bytes(env, argv[0], &seed);
}
