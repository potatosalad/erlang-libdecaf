{% from 'c_src/nif/xof/api_lifecycle.c.inc' import lifecycle %}
{% from 'c_src/nif/xof/kt_primitive.c.inc' import primitive as kt_primitive %}
{% from 'c_src/nif/sp800185/parallelhash_primitive.c.inc' import primitive as parallel_primitive %}
{% from 'c_src/nif/sp800185/framing.c.inc' import framing %}
{% from 'c_src/nif/sp800185/kmac_prefix.c.inc' import prefix as kmac_prefix %}
{% from 'c_src/nif/xof/cshake_prefix.c.inc' import prefix as cshake_prefix %}
{% macro implementation(f) %}
{% set p=f.prefix %}
#include <keccak_internal.h>
#include "{{ f.basename }}.h"
#include <decaf/sha512.h>
#include <decaf/shake.h>
#include <assert.h>

{% if f.name in ('cshake', 'kmac', 'tuplehash', 'parallelhash') %}
{{ framing(p, right=f.name in ('kmac', 'tuplehash', 'parallelhash'), domain=f.name in ('tuplehash', 'parallelhash'), binary=f.name != 'cshake') }}
{% endif %}
{% if f.name in ('kt', 'hopmac') %}
{{ kt_primitive(p) }}

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
    {{ p }}_raw_ctx_t raw;
{% else %}
    decaf_keccak_sponge_s raw;
{% endif %}
{% if f.name in ('kt', 'hopmac') %}
    {{ p }}_custom_t *custom;
{% endif %}
{% if f.name == 'hopmac' %}
    {{ p }}_raw_ctx_t outer;
    size_t prefix_remaining;
{% endif %}
    size_t output_len;
    bool hash_mode, squeezing;
} {{ p }}_ctx_t;

static void
{{ p }}_clone({{ p }}_ctx_t *dest, const {{ p }}_ctx_t *source)
{
    *dest = *source;
{% if f.name in ('kt', 'hopmac') %}
    if (dest->custom != NULL)
        enif_keep_resource(dest->custom);
{% endif %}
}

static void
{{ p }}_destroy({{ p }}_ctx_t *state)
{
{% if f.name in ('kt', 'hopmac') %}
    if (state->custom != NULL)
        enif_release_resource(state->custom);
{% endif %}
    decaf_bzero(state, sizeof(*state));
}

static void
{{ p }}_update({{ p }}_ctx_t *state, const uint8_t *data, size_t length)
{
{% if f.name == 'hopmac' %}
    if (state->prefix_remaining != 0) {
        size_t take = length < state->prefix_remaining ? length : state->prefix_remaining;
        {{ p }}_raw_update(&state->outer, data, take);
        state->prefix_remaining -= take;
        data += take;
        length -= take;
    }
{% endif %}
{% if f.name in ('kt', 'hopmac', 'parallelhash') %}
    {{ p }}_raw_update(&state->raw, data, length);
{% elif f.name == 'sha2' %}
    decaf_sha512_update(&state->raw, data, length);
{% else %}
    decaf_sha3_update(&state->raw, data, length);
{% endif %}
}

static size_t
{{ p }}_input_cost(const {{ p }}_ctx_t *state)
{
{% if f.name == 'parallelhash' %}
    return {{ p }}_raw_input_cost(&state->raw);
{% else %}
    (void)state;
    return 1;
{% endif %}
}

static bool
{{ p }}_valid(const {{ p }}_ctx_t *state)
{
{% if f.name == 'parallelhash' %}
    return !state->raw.overflow;
{% else %}
    (void)state;
    return true;
{% endif %}
}

static bool
{{ p }}_finish({{ p }}_ctx_t *state)
{
    if (state->squeezing)
        return true;
{% if f.name in ('kmac', 'tuplehash') %}
    uint8_t encoded[sizeof(size_t) + 1];
    size_t length = {{ p }}_right_encode(state->hash_mode ? state->output_len * 8 : 0, encoded);
    decaf_sha3_update(&state->raw, encoded, length);
{% elif f.name == 'parallelhash' %}
    {{ p }}_raw_finish_root(&state->raw, state->hash_mode ? state->output_len * 8 : 0);
{% elif f.name == 'hopmac' %}
    uint8_t digest[64], dummy;
    size_t length = state->raw.chaining_len;
    {{ p }}_raw_output(&state->raw, digest, length);
    {{ p }}_raw_update(&state->outer, digest, length);
    state->outer.customization_len = length;
    {{ p }}_raw_output(&state->outer, &dummy, 0);
    decaf_bzero(digest, sizeof(digest));
{% endif %}
    state->squeezing = true;
    return {{ p }}_valid(state);
}

static void
{{ p }}_output({{ p }}_ctx_t *state, uint8_t *output, size_t length)
{
{% if f.name == 'sha2' %}
    decaf_sha512_final(&state->raw, output, length);
{% elif f.name == 'hopmac' %}
    {{ p }}_raw_output(&state->outer, output, length);
{% elif f.name in ('kt', 'parallelhash') %}
    {{ p }}_raw_output(&state->raw, output, length);
{% else %}
    decaf_sha3_output(&state->raw, output, length);
{% endif %}
}

{% if f.name == 'kmac' %}
{{ kmac_prefix(p) }}
{% elif f.name == 'cshake' %}
{{ cshake_prefix(p) }}
{% endif %}

/* Selection and initialization are local to this component. Generic lifecycle
 * entry points only dispatch existing resources; they do not interpret options. */
static int
{{ p }}_create(ErlNifEnv *env, ERL_NIF_TERM type, bool hash_mode,
               ERL_NIF_TERM output_length, bool explicit_length, ERL_NIF_TERM key,
               ERL_NIF_TERM function_name, ERL_NIF_TERM customization,
               ERL_NIF_TERM block_size, ERL_NIF_TERM domain,
               {{ p }}_ctx_t *state, ERL_NIF_TERM *prefix)
{
    (void)key; (void)function_name; (void)customization; (void)block_size; (void)domain;
    size_t rate = 0, default_length = 0, maximum = SIZE_MAX;
    unsigned pad = 0, rounds = 0;
    bool selected = false, requires_length = false;
{% for a in ctx.crypto_profiles(f) %}
    if (enif_is_identical(type, ATOM({{ a.name }})) &&
        (hash_mode ? {{ 'true' if a.hash_allowed else 'false' }} : {{ 'true' if a.xof_allowed else 'false' }})) {
        selected = true;
        rate = {{ a.rate }};
        default_length = {{ a.default }};
        maximum = {{ a.maximum if a.maximum is not none else 'SIZE_MAX' }};
        pad = {{ a.pad }};
        rounds = {{ a.rounds }};
        requires_length = {{ 'true' if a.requires_length else 'false' }};
    }
{% endfor %}
    if (!selected || (hash_mode && requires_length && !explicit_length))
        return 0;
    unsigned long length = default_length;
    if (explicit_length && !enif_get_ulong(env, output_length, &length))
        return 0;
    if (length > maximum{% if f.name in ('kmac', 'tuplehash', 'parallelhash') %} || (hash_mode && length > SIZE_MAX / 8){% endif %})
        return 0;
    state->hash_mode = hash_mode;
    state->output_len = length;
    *prefix = enif_make_list(env, 0);
    (void)rate; (void)pad; (void)rounds;
{% if f.name == 'sha2' %}
    decaf_sha512_init(&state->raw);
{% elif f.name in ('kt', 'hopmac') %}
    {{ p }}_raw_init(&state->raw, rate);
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
    {{ p }}_raw_init(&state->outer, rate);
    state->prefix_remaining = key_binary.size;
    *prefix = key;
{% endif %}
{% elif f.name == 'parallelhash' %}
    unsigned long size;
    if (!enif_get_ulong(env, block_size, &size) || size == 0)
        return 0;
    {{ p }}_raw_init(&state->raw, rate);
    state->raw.block_size = size;
    ERL_NIF_TERM name_prefix, encoded_size;
    size_t prefix_length;
    int status = {{ p }}_domain_prefix(env, rate, "ParallelHash", 12, customization, &name_prefix, &prefix_length);
    if (status != 1)
        return status;
    uint8_t encoded[sizeof(size_t) + 1];
    size_t encoded_length = {{ p }}_left_encode(size, encoded);
    if (!{{ p }}_binary(env, encoded, encoded_length, &encoded_size))
        return -1;
    *prefix = enif_make_list2(env, name_prefix, encoded_size);
    state->raw.prefix_remaining = prefix_length + encoded_length;
{% else %}
{% if f.name == 'turboshake' %}
    unsigned value;
    if (!enif_get_uint(env, domain, &value) || value < 1 || value > 127)
        return 0;
    pad = value;
{% elif f.name in ('tuplehash', 'kmac') %}
    pad = 0x04;
{% endif %}
    decaf_kparams_s params = {0, 'A', (uint8_t)rate, (uint8_t)rounds, (uint8_t)pad, 0x80, 0xFF, 0xFF};
    decaf_sha3_init(&state->raw, &params);
{% if f.name == 'cshake' %}
    bool customized;
    int status = {{ p }}_prefix(env, rate, function_name, customization, prefix, &customized);
    if (status != 1)
        return status;
    if (customized)
        state->raw.params->pad = 0x04;
{% elif f.name == 'kmac' %}
    return {{ p }}_prefix(env, rate, key, customization, prefix);
{% elif f.name == 'tuplehash' %}
    size_t prefix_length;
    return {{ p }}_domain_prefix(env, rate, "TupleHash", 9, customization, prefix, &prefix_length);
{% endif %}
{% endif %}
    return 1;
}

{{ lifecycle(f) }}
{% endmacro %}
