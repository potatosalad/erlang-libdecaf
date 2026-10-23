{% from 'c_src/nif/algorithm.c.inc' import entry_points with context %}
{% from 'c_src/nif/parallelhash/primitive.c.inc' import primitive as parallel_primitive %}
{% from 'c_src/nif/kmac/prefix.c.inc' import prefix as kmac_prefix %}
{% from 'c_src/nif/cshake/prefix.c.inc' import prefix as cshake_prefix %}
{% macro implementation(f) %}
{% set p=f.prefix %}
{% set rawp='libdecaf_nif_kt' if f.name in ('kt', 'hopmac') else p %}
{% if f.name == 'sha2' %}
#include <decaf/sha512.h>
{% elif f.name in ('sha3', 'keccak', 'cshake', 'parallelhash') %}
#include <keccak_internal.h>
#include <decaf/shake.h>
{% elif f.name in ('kmac', 'tuplehash', 'turboshake') %}
#include <decaf/shake.h>
{% endif %}
#include "{{ f.basename }}.h"
{% if f.name in ('kmac', 'tuplehash', 'parallelhash') %}
#include "../cshake/cshake.h"
{% endif %}
{% if f.name in ('cshake', 'kmac', 'tuplehash', 'parallelhash') %}
#include "{{ 'sp800185.h' if f.name == 'cshake' else '../cshake/sp800185.h' }}"
{% endif %}
{% if f.name in ('kt', 'hopmac') %}
#include "../kt/kt_primitive.h"
{% elif f.name == 'turboshake' %}
#include "turboshake_primitive.h"
{% endif %}

{% if f.name in ('kt', 'hopmac') %}

/* Immutable customization is retained independently of private contexts. */
typedef struct {
    size_t size;
    uint8_t data[];
} {{ p }}_custom_t;
static ErlNifResourceType *{{ p }}_custom_resource_type;
static void
{{ p }}_custom_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    {{ p }}_custom_t *custom = obj;
    decaf_bzero(custom->data, custom->size);
}
{% elif f.name == 'parallelhash' %}
{{ parallel_primitive(p) }}
{% endif %}

typedef struct {
{% if f.name == 'sha2' %}
    struct decaf_sha512_ctx_s raw;
{% elif f.name in ('kt', 'hopmac', 'parallelhash') %}
    {{ rawp }}_raw_ctx_t raw;
{% else %}
    decaf_keccak_sponge_s raw;
{% endif %}
{% if f.name in ('kt', 'hopmac') %}
    {{ p }}_custom_t *custom;
{% endif %}
{% if f.name == 'hopmac' %}
    {{ rawp }}_raw_ctx_t outer;
    size_t prefix_remaining;
{% endif %}
} {{ p }}_ctx_t;

static void
{{ p }}_clone(void *destination, const void *original)
{
    {{ p }}_ctx_t *dest = destination;
    const {{ p }}_ctx_t *source = original;
    *dest = *source;
{% if f.name in ('kt', 'hopmac') %}
    if (dest->custom != NULL)
        enif_keep_resource(dest->custom);
{% endif %}
}

static void
{{ p }}_destroy(void *context)
{
    {{ p }}_ctx_t *state = context;
{% if f.name in ('kt', 'hopmac') %}
    if (state->custom != NULL)
        enif_release_resource(state->custom);
{% endif %}
    decaf_bzero(state, sizeof(*state));
}

static void
{{ p }}_update(void *context, const uint8_t *data, size_t length)
{
    {{ p }}_ctx_t *state = context;
{% if f.name == 'hopmac' %}
    if (state->prefix_remaining != 0) {
        size_t take = length < state->prefix_remaining ? length : state->prefix_remaining;
        {{ rawp }}_raw_update(&state->outer, data, take);
        state->prefix_remaining -= take;
        data += take;
        length -= take;
    }
{% endif %}
{% if f.name in ('kt', 'hopmac', 'parallelhash') %}
    {{ rawp }}_raw_update(&state->raw, data, length);
{% elif f.name == 'turboshake' %}
    libdecaf_nif_turboshake_absorb(&state->raw, data, length);
{% elif f.name == 'sha2' %}
    decaf_sha512_update(&state->raw, data, length);
{% else %}
    decaf_sha3_update(&state->raw, data, length);
{% endif %}
}

static size_t
{{ p }}_input_cost(const void *context)
{
    const {{ p }}_ctx_t *state = context;
{% if f.name == 'parallelhash' %}
    return {{ rawp }}_raw_input_cost(&state->raw);
{% else %}
    (void)state;
    return 1;
{% endif %}
}

static bool
{{ p }}_valid(const void *context)
{
    const {{ p }}_ctx_t *state = context;
{% if f.name == 'parallelhash' %}
    return !state->raw.overflow;
{% else %}
    (void)state;
    return true;
{% endif %}
}

{% for mode in ('hash', 'xof') %}
{% if (f.hash_algorithms if mode == 'hash' else f.xof_algorithms) %}
static bool
{{ p }}_{{ mode }}_finish(void *context{% if mode == 'hash' %}, size_t output_len{% endif %})
{
    {{ p }}_ctx_t *state = context;
{% if mode == 'hash' %}
    (void)output_len;
{% endif %}
{% if f.name in ('kmac', 'tuplehash') %}
    uint8_t encoded[sizeof(size_t) + 1];
    size_t length = libdecaf_nif_sp800185_right_encode({{ 'output_len * 8' if mode == 'hash' else '0' }}, encoded);
    decaf_sha3_update(&state->raw, encoded, length);
{% elif f.name == 'parallelhash' %}
    {{ rawp }}_raw_finish_root(&state->raw, {{ 'output_len * 8' if mode == 'hash' else '0' }});
{% elif f.name == 'hopmac' %}
    uint8_t digest[64], dummy;
    size_t length = state->raw.chaining_len;
    {{ rawp }}_raw_output(&state->raw, digest, length);
    {{ rawp }}_raw_update(&state->outer, digest, length);
    state->outer.customization_len = length;
    {{ rawp }}_raw_output(&state->outer, &dummy, 0);
    decaf_bzero(digest, sizeof(digest));
{% endif %}
    return {{ p }}_valid(state);
}

{% endif %}
{% endfor %}

static void
{{ p }}_output(void *context, uint8_t *output, size_t length)
{
    {{ p }}_ctx_t *state = context;
{% if f.name == 'sha2' %}
    decaf_sha512_final(&state->raw, output, length);
{% elif f.name == 'hopmac' %}
    {{ rawp }}_raw_output(&state->outer, output, length);
{% elif f.name in ('kt', 'parallelhash') %}
    {{ rawp }}_raw_output(&state->raw, output, length);
{% elif f.name == 'turboshake' %}
    libdecaf_nif_turboshake_squeeze(&state->raw, output, length);
{% else %}
    decaf_sha3_output(&state->raw, output, length);
{% endif %}
}

{% if f.name == 'kmac' %}
{{ kmac_prefix(p) }}
{% elif f.name == 'cshake' %}
{{ cshake_prefix(p) }}
{% endif %}

/* Each component accepts only its own initialization parameters. */
static int
{{ p }}_create({% if f.name != 'sha2' %}ErlNifEnv *env, {% endif %}{{ p }}_ctx_t *state{% if f.name != 'sha2' %}, size_t rate{% endif %}{% if f.name in ('sha3', 'keccak') %}, unsigned pad{% elif f.name == 'turboshake' %}, ERL_NIF_TERM domain{% elif f.name == 'cshake' %}, ERL_NIF_TERM function_name, ERL_NIF_TERM customization, ERL_NIF_TERM *prefix{% elif f.name in ('kmac', 'hopmac') %}, ERL_NIF_TERM key, ERL_NIF_TERM customization, ERL_NIF_TERM *prefix{% elif f.name == 'parallelhash' %}, ERL_NIF_TERM block_size, ERL_NIF_TERM customization, ERL_NIF_TERM *prefix{% elif f.name == 'tuplehash' %}, ERL_NIF_TERM customization, ERL_NIF_TERM *prefix{% elif f.name == 'kt' %}, ERL_NIF_TERM customization{% endif %})
{
{% if f.name in ('sha3', 'keccak') %}
    (void)env;
{% endif %}
{% if f.name == 'sha2' %}
    decaf_sha512_init(&state->raw);
{% elif f.name in ('kt', 'hopmac') %}
    {{ rawp }}_raw_init(&state->raw, rate);
    ErlNifBinary custom;
    if (!enif_inspect_iolist_as_binary(env, customization, &custom) ||
        custom.size > SIZE_MAX - sizeof({{ p }}_custom_t))
        return 0;
    if (custom.size != 0) {
        state->custom = enif_alloc_resource({{ p }}_custom_resource_type, sizeof(*state->custom) + custom.size);
        if (state->custom == NULL)
            return -1;
        state->custom->size = custom.size;
        memcpy(state->custom->data, custom.data, custom.size);
    }
    state->raw.customization_len = custom.size;
{% if f.name == 'hopmac' %}
    ErlNifBinary key_binary;
    if (!enif_inspect_iolist_as_binary(env, key, &key_binary))
        return 0;
    {{ rawp }}_raw_init(&state->outer, rate);
    state->prefix_remaining = key_binary.size;
    *prefix = key;
{% endif %}
{% elif f.name == 'parallelhash' %}
    unsigned long size;
    if (!enif_get_ulong(env, block_size, &size) || size == 0)
        return 0;
    {{ rawp }}_raw_init(&state->raw, rate);
    state->raw.block_size = size;
    ERL_NIF_TERM name_prefix, encoded_size;
    size_t prefix_length;
    int status = libdecaf_nif_cshake_init(env, &state->raw.root, rate,
        enif_make_string(env, "ParallelHash", ERL_NIF_LATIN1), customization, &name_prefix, &prefix_length);
    if (status != 1)
        return status;
    uint8_t encoded[sizeof(size_t) + 1];
    size_t encoded_length = libdecaf_nif_sp800185_left_encode(size, encoded);
    if (!libdecaf_nif_sp800185_binary(env, encoded, encoded_length, &encoded_size))
        return -1;
    *prefix = enif_make_list2(env, name_prefix, encoded_size);
    state->raw.prefix_remaining = prefix_length + encoded_length;
{% elif f.name == 'cshake' %}
    size_t prefix_length;
    return libdecaf_nif_cshake_init(env, &state->raw, rate, function_name, customization, prefix, &prefix_length);
{% elif f.name == 'kmac' %}
    return {{ p }}_prefix(env, &state->raw, rate, key, customization, prefix);
{% elif f.name == 'tuplehash' %}
    size_t prefix_length;
    return libdecaf_nif_cshake_init(env, &state->raw, rate,
        enif_make_string(env, "TupleHash", ERL_NIF_LATIN1), customization, prefix, &prefix_length);
{% elif f.name == 'turboshake' %}
    unsigned value;
    if (!enif_get_uint(env, domain, &value) || value < 1 || value > 127)
        return 0;
    libdecaf_nif_turboshake_init(&state->raw, rate, (uint8_t)value);
{% else %}
    decaf_kparams_s params = {0, 'A', (uint8_t)rate, 0, (uint8_t)pad, 0x80, 0xFF, 0xFF};
    decaf_sha3_init(&state->raw, &params);
{% endif %}
    return 1;
}

{% if f.name == 'tuplehash' %}
static void
{{ p }}_element(void *context, size_t size)
{
    {{ p }}_ctx_t *state = context;
    uint8_t encoded[sizeof(size_t) + 1];
    size_t length = libdecaf_nif_sp800185_left_encode(size * 8, encoded);
    decaf_sha3_update(&state->raw, encoded, length);
}
{% endif %}
{% if f.name in ('kt', 'hopmac') %}
static void
{{ p }}_suffix(const void *context, const uint8_t **data, size_t *size)
{
    const {{ p }}_ctx_t *state = context;
    *data = state->custom != NULL ? state->custom->data : NULL;
    *size = state->custom != NULL ? state->custom->size : 0;
}

int
{{ p }}_load(ErlNifEnv *env)
{
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    {{ p }}_custom_resource_type = enif_open_resource_type(env, "libdecaf_nif", "{{ p }}_custom",
        {{ p }}_custom_dtor, flags, NULL);
    return {{ p }}_custom_resource_type != NULL ? 0 : -1;
}
{% endif %}

{% for algorithm in ctx.crypto_algorithms(f) %}
{{ entry_points(f, algorithm) }}
{% endfor %}
{% endmacro %}
