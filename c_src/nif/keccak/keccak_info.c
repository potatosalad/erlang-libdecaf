#include "keccak_info.h"
#include <keccak_internal.h>

ERL_NIF_TERM
libdecaf_nif_keccak_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argv;
    if (argc != 0)
        return enif_make_badarg(env);
    const char *backend = decaf_keccak_backend();
    size_t length = strlen(backend);
    ERL_NIF_TERM name;
    uint8_t *data = enif_make_new_binary(env, length, &name);
    if (data == NULL)
        return EXCP_ERROR(env, "Could not allocate Keccak backend name");
    memcpy(data, backend, length);
    ERL_NIF_TERM keys[] = {ATOM(backend), ATOM(parallelism)};
    ERL_NIF_TERM values[] = {name, enif_make_uint(env, decaf_keccak_parallelism())};
    ERL_NIF_TERM info;
    if (!enif_make_map_from_arrays(env, keys, values, 2, &info))
        return EXCP_ERROR(env, "Could not create Keccak backend info");
    return info;
}
