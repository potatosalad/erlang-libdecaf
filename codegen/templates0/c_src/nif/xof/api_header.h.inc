{% macro header(f) %}
#ifndef LIBDECAF_NIF_{{ f.name | upper }}_API_H
#define LIBDECAF_NIF_{{ f.name | upper }}_API_H
#include "../libdecaf_nif.h"
#include <stdbool.h>

int {{ f.prefix }}_load(ErlNifEnv *env);
bool {{ f.prefix }}_accepts(ErlNifEnv *env, ERL_NIF_TERM term, bool hash_mode);
ERL_NIF_TERM {{ f.prefix }}_hash_update(ErlNifEnv *, int, const ERL_NIF_TERM []);
ERL_NIF_TERM {{ f.prefix }}_hash_final(ErlNifEnv *, int, const ERL_NIF_TERM []);
{% if f.xof_algorithms %}
ERL_NIF_TERM {{ f.prefix }}_xof_absorb(ErlNifEnv *, int, const ERL_NIF_TERM []);
ERL_NIF_TERM {{ f.prefix }}_xof_squeeze(ErlNifEnv *, int, const ERL_NIF_TERM []);
{% endif %}
{% for fun in f.functions('hash') + f.functions('xof') %}
ERL_NIF_TERM {{ fun.c_name }}(ErlNifEnv *, int, const ERL_NIF_TERM []);
{% endfor %}
#endif
{% endmacro %}
