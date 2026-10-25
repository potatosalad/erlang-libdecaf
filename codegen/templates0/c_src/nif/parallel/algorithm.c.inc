static size_t
{{ p }}_parallel_block_size(const void *context)
{
{% if f.name == 'parallelhash' %}
    const {{ p }}_ctx_t *state = context;
    return state->raw.block_size;
{% else %}
    (void)context;
    return 8192;
{% endif %}
}

static size_t
{{ p }}_parallel_prefix(const void *context)
{
    const {{ p }}_ctx_t *state = context;
{% if f.name == 'parallelhash' %}
    return state->raw.leaf_len == 0 ? 0 : state->raw.block_size - state->raw.leaf_len;
{% else %}
    if (!state->raw.tree && state->raw.root_len < 8192)
        return 8192 - state->raw.root_len;
    return state->raw.leaf_len == 0 ? 0 : 8192 - state->raw.leaf_len;
{% endif %}
}

static libdecaf_nif_parallel_leaf_t
{{ p }}_parallel_leaf(const void *context)
{
    const {{ p }}_ctx_t *state = context;
    return (libdecaf_nif_parallel_leaf_t){
        .rate = {{ 'state->raw.root.params->rate' if f.name == 'parallelhash' else 'state->raw.rate' }},
        .turbo = {{ 'false' if f.name == 'parallelhash' else 'true' }}
    };
}

static bool
{{ p }}_parallel_join(void *context, const uint8_t *chaining_values, size_t count)
{
    {{ p }}_ctx_t *state = context;
{% if f.name == 'parallelhash' %}
    if (count > SIZE_MAX - state->raw.block_count) {
        state->raw.overflow = true;
        return false;
    }
    decaf_sha3_update(&state->raw.root, chaining_values, count * state->raw.chaining_len);
    state->raw.block_count += count;
    return true;
{% else %}
    return libdecaf_nif_kt_raw_join(&state->raw, chaining_values, count);
{% endif %}
}

static const libdecaf_nif_parallel_algorithm_t {{ p }}_parallel_algorithm = {
    .block_size = {{ p }}_parallel_block_size,
    .prefix = {{ p }}_parallel_prefix,
    .leaf = {{ p }}_parallel_leaf,
    .update = {{ p }}_update,
    .join = {{ p }}_parallel_join,
};
