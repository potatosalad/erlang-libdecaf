{% macro primitive(p) %}
/* The inner sponge absorbs each B-byte block incrementally. No B-byte
 * allocation or unbounded input buffering is required by this representation. */
typedef struct {
    decaf_keccak_sponge_s root, leaf;
    size_t block_size, leaf_len, block_count, chaining_len, prefix_remaining;
    bool finalized, overflow;
} {{ p }}_raw_ctx_t;



static void
{{ p }}_raw_init({{ p }}_raw_ctx_t *state, size_t rate)
{
    decaf_bzero(state, sizeof(*state));
    decaf_kparams_s params = {0, 'A', (uint8_t)rate, 0, 0x04, 0x80, 0xFF, 0xFF};
    decaf_sha3_init(&state->root, &params);
    params.pad = 0x1F;
    decaf_sha3_init(&state->leaf, &params);
    state->chaining_len = 200 - rate;
}

static void
{{ p }}_raw_emit_leaf({{ p }}_raw_ctx_t *state)
{
    if (state->block_count == SIZE_MAX) {
        state->overflow = true;
        return;
    }
    uint8_t chaining[64];
    decaf_sha3_output(&state->leaf, chaining, state->chaining_len);
    decaf_sha3_update(&state->root, chaining, state->chaining_len);
    decaf_bzero(chaining, sizeof(chaining));
    decaf_sha3_reset(&state->leaf);
    state->leaf_len = 0;
    state->block_count++;
}

static void
{{ p }}_raw_update({{ p }}_raw_ctx_t *state, const uint8_t *input, size_t length)
{
    if (state->prefix_remaining != 0) {
        size_t take = length < state->prefix_remaining ? length : state->prefix_remaining;
        decaf_sha3_update(&state->root, input, take);
        state->prefix_remaining -= take;
        input += take;
        length -= take;
    }
    while (length != 0 && !state->overflow) {
        size_t take = state->block_size - state->leaf_len;
        if (take > length)
            take = length;
        decaf_sha3_update(&state->leaf, input, take);
        state->leaf_len += take;
        input += take;
        length -= take;
        if (state->leaf_len == state->block_size)
            {{ p }}_raw_emit_leaf(state);
    }
}

static size_t
{{ p }}_raw_input_cost(const {{ p }}_raw_ctx_t *state)
{
    /* Charge for leaf padding/permutations and chaining output as well as
     * input bytes, so B=1 cannot perform thousands of hashes in one slice. */
    size_t overhead = 2 * state->root.params->rate + state->chaining_len;
    return 1 + overhead / state->block_size + (overhead % state->block_size != 0);
}

static void
{{ p }}_raw_finish_root({{ p }}_raw_ctx_t *state, size_t encoded_length)
{
    if (state->finalized)
        return;
    if (state->leaf_len != 0)
        {{ p }}_raw_emit_leaf(state);
    if (state->overflow)
        return;
    uint8_t encoded[2 * (sizeof(size_t) + 1)];
    size_t length = {{ p }}_right_encode(state->block_count, encoded);
    length += {{ p }}_right_encode(encoded_length, encoded + length);
    decaf_sha3_update(&state->root, encoded, length);
    state->finalized = true;
}

static void
{{ p }}_raw_output({{ p }}_raw_ctx_t *state, uint8_t *output, size_t length)
{
    decaf_sha3_output(&state->root, output, length);
}




{% endmacro %}
