{% macro header(f, algorithms) %}
#ifndef LIBDECAF_NIF_{{ f.name | upper }}_H
#define LIBDECAF_NIF_{{ f.name | upper }}_H

{% if f.hash_algorithms %}
#include "../hash/hash.h"
{% endif %}
{% if f.xof_algorithms %}
#include "../xof/xof.h"
{% endif %}

{% if f.name == 'cshake' %}
struct decaf_keccak_sponge_s;
{% endif %}

#ifdef __cplusplus
extern "C" {
#endif

{% if f.name == 'cshake' %}
extern int libdecaf_nif_cshake_init(ErlNifEnv *env, struct decaf_keccak_sponge_s *state, size_t rate,
                                 ERL_NIF_TERM function_name, ERL_NIF_TERM customization,
                                 ERL_NIF_TERM *prefix, size_t *prefix_length);
{% endif %}
{% if f.name in ('kt', 'hopmac') %}
extern int {{ f.prefix }}_load(ErlNifEnv *env);
{% endif %}
{% for algorithm in algorithms %}
{% for mode in ('hash', 'xof') if algorithm.functions(mode, 'init') %}
extern const libdecaf_nif_{{ mode }}_algorithm_t {{ algorithm.symbol }}_{{ mode }}_algorithm;
{% endfor %}
{% for function in algorithm.exports %}
extern ERL_NIF_TERM {{ function.c_name }}(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
{% endfor %}
{% endfor %}

#ifdef __cplusplus
}
#endif

#endif
{% endmacro %}
