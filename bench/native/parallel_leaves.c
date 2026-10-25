/* Leaf-kernel upper bound: the same archive and wrappers as the NIF, without
 * Erlang scheduling, queues, root absorption, or hash framing. */
#include "../../c_src/nif/parallel/leaf.h"
#include <decaf/common.h>
#include <keccak_internal.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { BLOCK_SIZE = 8192, MAX_THREADS = 1024 };

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t start, done;
    unsigned int generation, completed, threads, width;
    bool stop;
    size_t leaves, passes;
    const uint8_t *input;
    uint8_t *output;
    libdecaf_nif_parallel_leaf_t algorithm;
} pool_t;

typedef struct {
    pool_t *pool;
    unsigned int number;
} worker_t;

static void
check(int result)
{
    if (result != 0) {
        fprintf(stderr, "pthread: %s\n", strerror(result));
        exit(1);
    }
}

static size_t
setting(const char *name, size_t fallback)
{
    const char *value = getenv(name);
    if (value == NULL)
        return fallback;
    char *end;
    errno = 0;
    unsigned long long number = strtoull(value, &end, 10);
    if (errno || value[0] < '0' || value[0] > '9' || *end || number == 0 || number > SIZE_MAX) {
        fprintf(stderr, "Invalid %s\n", name);
        exit(1);
    }
    return (size_t)number;
}

static double
seconds(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0)
        abort();
    return (double)time.tv_sec + (double)time.tv_nsec * 1e-9;
}

static void *
worker(void *argument)
{
    worker_t *self = argument;
    pool_t *pool = self->pool;
    unsigned int generation = 0;
    check(pthread_mutex_lock(&pool->mutex));
    for (;;) {
        while (!pool->stop && generation == pool->generation)
            check(pthread_cond_wait(&pool->start, &pool->mutex));
        if (pool->stop)
            break;
        generation = pool->generation;
        size_t groups = (pool->leaves + pool->width - 1) / pool->width;
        size_t first = groups * self->number / pool->threads * pool->width;
        size_t end = groups * (self->number + 1) / pool->threads * pool->width;
        if (end > pool->leaves)
            end = pool->leaves;
        check(pthread_mutex_unlock(&pool->mutex));
        for (size_t pass = 0; pass < pool->passes; pass++) {
            for (size_t index = first; index < end;) {
                unsigned int width = pool->width;
                while (width > end - index)
                    width /= 2;
                const uint8_t *inputs[8];
                uint8_t *outputs[8];
                for (unsigned int lane = 0; lane < width; lane++) {
                    inputs[lane] = pool->input + (index + lane) * BLOCK_SIZE;
                    outputs[lane] = pool->output + (index + lane) * (200 - pool->algorithm.rate);
                }
                libdecaf_nif_parallel_leaf_hash_many(pool->algorithm, inputs, BLOCK_SIZE, outputs, width);
                index += width;
            }
        }
        check(pthread_mutex_lock(&pool->mutex));
        if (++pool->completed == pool->threads)
            check(pthread_cond_signal(&pool->done));
    }
    check(pthread_mutex_unlock(&pool->mutex));
    return NULL;
}

static double
run(pool_t *pool, size_t passes)
{
    check(pthread_mutex_lock(&pool->mutex));
    pool->completed = 0;
    pool->passes = passes;
    double started = seconds();
    ++pool->generation;
    check(pthread_cond_broadcast(&pool->start));
    while (pool->completed != pool->threads)
        check(pthread_cond_wait(&pool->done, &pool->mutex));
    double elapsed = seconds() - started;
    check(pthread_mutex_unlock(&pool->mutex));
    return elapsed;
}

static int
compare(const void *left, const void *right)
{
    double a = *(const double *)left, b = *(const double *)right;
    return (a > b) - (a < b);
}

int
main(void)
{
    size_t mib = setting("BENCH_MIB", 64), gib = setting("BENCH_GIB", 16);
    size_t repeats = setting("BENCH_REPEATS", 3);
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    size_t threads = setting("BENCH_THREADS", online > 0 ? (size_t)online : 1);
    if (mib > SIZE_MAX / (1024 * 1024) || gib > SIZE_MAX / 1024 || gib * 1024 % mib != 0 || threads > MAX_THREADS ||
        repeats > 1000) {
        fprintf(stderr, "Sizes overflow, BENCH_MIB does not divide BENCH_GIB * 1024, or thread/repeat limit exceeded\n");
        return 1;
    }
    size_t bytes = mib * 1024 * 1024, leaves = bytes / BLOCK_SIZE;
    uint8_t *input = malloc(bytes), *output = malloc(leaves * 64);
    double *samples = calloc(repeats, sizeof(*samples));
    pthread_t *handles = calloc(threads, sizeof(*handles));
    worker_t *workers = calloc(threads, sizeof(*workers));
    if (input == NULL || output == NULL || samples == NULL || handles == NULL || workers == NULL)
        return 1;
    /* The streaming benchmark reuses a zero-filled input of this size too. */
    decaf_bzero(input, bytes);
    pool_t pool = {.mutex = PTHREAD_MUTEX_INITIALIZER,
                   .start = PTHREAD_COND_INITIALIZER,
                   .done = PTHREAD_COND_INITIALIZER,
                   .threads = (unsigned int)threads,
                   .width = decaf_keccak_parallelism(),
                   .leaves = leaves,
                   .input = input,
                   .output = output};
    for (unsigned int i = 0; i < threads; i++) {
        workers[i] = (worker_t){.pool = &pool, .number = i};
        check(pthread_create(&handles[i], NULL, worker, &workers[i]));
    }
    printf("Backend: %s; SIMD width: %u; threads: %zu; reused input: %zu MiB\n", decaf_keccak_backend(), pool.width, threads, mib);
    puts("Leaf-only upper bound: excludes root absorption, queues, and Erlang scheduling.\n");
    printf("%-18s %12s %12s %12s\n", "Algorithm", "Median GiB/s", "Min GiB/s", "Max GiB/s");
    const char *names[] = {"kt128", "kt256", "parallelhash128", "parallelhash256"};
    for (unsigned int algorithm = 0; algorithm < 4; algorithm++) {
        pool.algorithm = (libdecaf_nif_parallel_leaf_t){.rate = algorithm % 2 == 0 ? 168 : 136, .turbo = algorithm < 2};
        run(&pool, 1);
        /* Verify each worker's range and all SIMD lanes against scalar hashing. */
        uint8_t expected[64];
        libdecaf_nif_parallel_leaf_hash(pool.algorithm, input, BLOCK_SIZE, expected);
        size_t length = 200 - pool.algorithm.rate;
        for (size_t i = 0; i < leaves; i++) {
            if (memcmp(expected, output + i * length, length) != 0) {
                fprintf(stderr, "Leaf validation failed: %s, %zu\n", names[algorithm], i);
                return 1;
            }
        }
        for (size_t repeat = 0; repeat < repeats; repeat++)
            samples[repeat] = (double)gib / run(&pool, gib * 1024 / mib);
        qsort(samples, repeats, sizeof(*samples), compare);
        double median = repeats % 2 ? samples[repeats / 2] : (samples[repeats / 2 - 1] + samples[repeats / 2]) / 2;
        printf("%-18s %12.2f %12.2f %12.2f\n", names[algorithm], median, samples[0], samples[repeats - 1]);
        fflush(stdout);
        decaf_bzero(expected, sizeof(expected));
    }
    check(pthread_mutex_lock(&pool.mutex));
    pool.stop = true;
    check(pthread_cond_broadcast(&pool.start));
    check(pthread_mutex_unlock(&pool.mutex));
    for (size_t i = 0; i < threads; i++)
        check(pthread_join(handles[i], NULL));
    check(pthread_cond_destroy(&pool.start));
    check(pthread_cond_destroy(&pool.done));
    check(pthread_mutex_destroy(&pool.mutex));
    decaf_bzero(output, leaves * 64);
    free(workers);
    free(handles);
    free(samples);
    free(output);
    free(input);
    return 0;
}
