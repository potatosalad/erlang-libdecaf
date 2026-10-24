#include "phash.h"

#define LIBDECAF_PHASH_WORKER_LIMIT (1024)

/* Only atoms are retained; the configuration is fixed for the lifetime of the VM. */
static unsigned int libdecaf_nif_phash_worker_count = 0;
static ERL_NIF_TERM libdecaf_nif_phash_worker_names[LIBDECAF_PHASH_WORKER_LIMIT];

int
libdecaf_nif_phash_load(ErlNifEnv *env)
{
    ErlNifSysInfo sys_info;
    unsigned int count;
    unsigned int i;
    char name[sizeof("libdecaf_phash_worker_") + 20];

    enif_system_info(&sys_info, sizeof(sys_info));
    count = sys_info.scheduler_threads > 0 ? (unsigned int)sys_info.scheduler_threads : 1;
    if (count > LIBDECAF_PHASH_WORKER_LIMIT) {
        count = LIBDECAF_PHASH_WORKER_LIMIT;
    }
    for (i = 0; i < count; i++) {
        int length = enif_snprintf(name, sizeof(name), "libdecaf_phash_worker_%llu", (unsigned long long)i + 1);
        if (length < 0 || (size_t)length >= sizeof(name)) {
            return -1;
        }
        libdecaf_nif_phash_worker_names[i] = enif_make_atom(env, name);
    }
    libdecaf_nif_phash_worker_count = count;
    return 0;
}

ERL_NIF_TERM
libdecaf_nif_phash_worker_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM keys[] = {ATOM(count), ATOM(limit), ATOM(names)};
    ERL_NIF_TERM values[] = {enif_make_uint(env, libdecaf_nif_phash_worker_count), enif_make_uint(env, LIBDECAF_PHASH_WORKER_LIMIT),
                             enif_make_list_from_array(env, libdecaf_nif_phash_worker_names, libdecaf_nif_phash_worker_count)};
    ERL_NIF_TERM info;
    (void)argv;

    if (argc != 0) {
        return EXCP_BADARG(env, "argc must be 0");
    }
    if (!enif_make_map_from_arrays(env, keys, values, 3, &info)) {
        return EXCP_ERROR(env, "Could not create parallel-hash worker info");
    }
    return info;
}
