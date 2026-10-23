{% macro declarations(ctx, group) %}
#ifndef LIBDECAF_NIF_{{ group.name | upper }}_H
#define LIBDECAF_NIF_{{ group.name | upper }}_H

#include "../libdecaf_nif.h"

#ifdef __cplusplus
extern "C" {
#endif

int libdecaf_nif_{{ group.name }}_load(ErlNifEnv *env);

{% for function in ctx.nif.functions if function.name.startswith(group.name + '_') %}
ERL_NIF_TERM {{ function.c_name }}(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
{% endfor %}

#ifdef __cplusplus
}
#endif

#endif
{% endmacro %}
