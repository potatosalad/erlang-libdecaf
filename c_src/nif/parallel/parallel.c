#include "parallel.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#define LIBDECAF_PARALLEL_ROUTER_LIMIT (1024)

/* Only atoms are retained; the configuration is fixed for the lifetime of the VM. */
static unsigned int libdecaf_nif_parallel_router_count = 0;
static ERL_NIF_TERM libdecaf_nif_parallel_router_names[LIBDECAF_PARALLEL_ROUTER_LIMIT];

int
libdecaf_nif_parallel_load(ErlNifEnv *env)
{
    ErlNifSysInfo sys_info;
    unsigned int count;
    unsigned int i;
    char name[sizeof("libdecaf_parallel_router_") + 20];

    enif_system_info(&sys_info, sizeof(sys_info));
    count = sys_info.scheduler_threads > 0 ? (unsigned int)sys_info.scheduler_threads : 1;
    if (count > LIBDECAF_PARALLEL_ROUTER_LIMIT) {
        count = LIBDECAF_PARALLEL_ROUTER_LIMIT;
    }
    for (i = 0; i < count; i++) {
        int length = enif_snprintf(name, sizeof(name), "libdecaf_parallel_router_%llu", (unsigned long long)i + 1);
        if (length < 0 || (size_t)length >= sizeof(name)) {
            return -1;
        }
        libdecaf_nif_parallel_router_names[i] = enif_make_atom(env, name);
    }
    libdecaf_nif_parallel_router_count = count;
    return 0;
}

ERL_NIF_TERM
libdecaf_nif_parallel_router_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM keys[] = {ATOM(count), ATOM(limit), ATOM(names)};
    ERL_NIF_TERM values[] = {
        enif_make_uint(env, libdecaf_nif_parallel_router_count), enif_make_uint(env, LIBDECAF_PARALLEL_ROUTER_LIMIT),
        enif_make_list_from_array(env, libdecaf_nif_parallel_router_names, libdecaf_nif_parallel_router_count)};
    ERL_NIF_TERM info;
    (void)argv;

    if (argc != 0) {
        return EXCP_BADARG(env, "argc must be 0");
    }
    if (!enif_make_map_from_arrays(env, keys, values, 3, &info)) {
        return EXCP_ERROR(env, "Could not create parallel router info");
    }
    return info;
}

ERL_NIF_TERM
libdecaf_nif_parallel_absorb_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argv;
    if (argc != 0) {
        return EXCP_BADARG(env, "argc must be 0");
    }

    /* Placeholder for parallel absorption. This function runs on a dirty CPU scheduler. */
#ifdef _WIN32
    Sleep(1000);
#else
    struct timespec remaining = {.tv_sec = 1, .tv_nsec = 0};
    while (nanosleep(&remaining, &remaining) != 0) {
        if (errno != EINTR) {
            return EXCP_ERROR(env, "Parallel absorb placeholder sleep failed");
        }
    }
#endif
    return ATOM(ok);
}
