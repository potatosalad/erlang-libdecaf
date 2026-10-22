#include "groups.h"
#include <decaf/point_255.h>
#include <decaf/point_448.h>

#define GROUP_JOIN_(A, B) A##B
#define GROUP_JOIN(A, B) GROUP_JOIN_(A, B)
#define GROUP_API(Name) GROUP_JOIN(GROUP_NS, Name)
#define GROUP_NIF(Name) GROUP_JOIN(GROUP_JOIN(libdecaf_nif_, GROUP_NAME), Name)

#define GROUP_NAME ristretto255
#define GROUP_NS decaf_255
#define GROUP_POINT_BYTES DECAF_255_SER_BYTES
#define GROUP_SCALAR_BYTES DECAF_255_SCALAR_BYTES
#include "impl/group.c.h"
#undef GROUP_NAME
#undef GROUP_NS
#undef GROUP_POINT_BYTES
#undef GROUP_SCALAR_BYTES

#define GROUP_NAME decaf448
#define GROUP_NS decaf_448
#define GROUP_POINT_BYTES DECAF_448_SER_BYTES
#define GROUP_SCALAR_BYTES DECAF_448_SCALAR_BYTES
#include "impl/group.c.h"
#undef GROUP_NAME
#undef GROUP_NS
#undef GROUP_POINT_BYTES
#undef GROUP_SCALAR_BYTES

int
libdecaf_nif_groups_load(ErlNifEnv *env)
{
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    libdecaf_nif_ristretto255_precomputed_type = enif_open_resource_type(env, "libdecaf_nif", "ristretto255_precomputed",
                                                                         libdecaf_nif_ristretto255_precomputed_dtor, flags, NULL);
    libdecaf_nif_decaf448_precomputed_type =
        enif_open_resource_type(env, "libdecaf_nif", "decaf448_precomputed", libdecaf_nif_decaf448_precomputed_dtor, flags, NULL);
    return libdecaf_nif_ristretto255_precomputed_type != NULL && libdecaf_nif_decaf448_precomputed_type != NULL ? 0 : -1;
}
