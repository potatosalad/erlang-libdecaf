{% macro primitive(p) %}



/* RFC 9861 length_encode differs from SP 800-185 right_encode at zero. */
static size_t
{{ p }}_raw_length_encode(size_t value, uint8_t *encoded)
{
    size_t bytes = 0;
    for (size_t remaining = value; remaining != 0; remaining >>= 8) {
        bytes++;
    }
    for (size_t i = 0; i < bytes; i++) {
        encoded[bytes - i - 1] = (uint8_t)(value >> (8 * i));
    }
    encoded[bytes] = (uint8_t)bytes;
    return bytes + 1;
}

void
{{ p }}_raw_init({{ p }}_raw_ctx_t *ctx, size_t rate)
{
    decaf_bzero(ctx, sizeof(*ctx));
    ctx->rate = rate;
    ctx->chaining_len = 200 - rate;
    libdecaf_nif_turboshake_init(&ctx->root, rate, 0x07);
    libdecaf_nif_turboshake_init(&ctx->leaf, rate, 0x0B);
}



bool
{{ p }}_raw_join({{ p }}_raw_ctx_t *ctx, const uint8_t *chaining_values, size_t count)
{
    assert(!ctx->finalized && ctx->root_len == 8192 && ctx->leaf_len == 0);
    if (count > SIZE_MAX - ctx->chaining_count)
        return false;
    if (!ctx->tree) {
        static const uint8_t divider[8] = {0x03, 0, 0, 0, 0, 0, 0, 0};
        libdecaf_nif_turboshake_absorb(&ctx->root, divider, sizeof(divider));
        ctx->root.params->pad = 0x06;
        ctx->tree = true;
    }
    libdecaf_nif_turboshake_absorb(&ctx->root, chaining_values, count * ctx->chaining_len);
    ctx->chaining_count += count;
    return true;
}

static void
{{ p }}_raw_emit_leaf({{ p }}_raw_ctx_t *ctx)
{
    uint8_t chaining_value[64];
    libdecaf_nif_turboshake_squeeze(&ctx->leaf, chaining_value, ctx->chaining_len);
    libdecaf_nif_turboshake_absorb(&ctx->root, chaining_value, ctx->chaining_len);
    decaf_bzero(chaining_value, sizeof(chaining_value));
    decaf_sha3_reset(&ctx->leaf);
    ctx->leaf_len = 0;
    ctx->chaining_count++;
}

void
{{ p }}_raw_update({{ p }}_raw_ctx_t *ctx, const uint8_t *input, size_t input_len)
{
    assert(!ctx->finalized);
    while (input_len != 0) {
        if (!ctx->tree && ctx->root_len == 8192) {
            static const uint8_t divider[8] = {0x03, 0, 0, 0, 0, 0, 0, 0};
            libdecaf_nif_turboshake_absorb(&ctx->root, divider, sizeof(divider));
            ctx->root.params->pad = 0x06;
            ctx->tree = true;
        }
        size_t remaining = 8192 - (ctx->tree ? ctx->leaf_len : ctx->root_len);
        size_t take = input_len < remaining ? input_len : remaining;
        if (ctx->tree) {
            libdecaf_nif_turboshake_absorb(&ctx->leaf, input, take);
            ctx->leaf_len += take;
            if (ctx->leaf_len == 8192) {
                {{ p }}_raw_emit_leaf(ctx);
            }
        } else {
            libdecaf_nif_turboshake_absorb(&ctx->root, input, take);
            ctx->root_len += take;
        }
        input += take;
        input_len -= take;
    }
}

void
{{ p }}_raw_output({{ p }}_raw_ctx_t *ctx, uint8_t *output, size_t output_len)
{
    if (!ctx->finalized) {
        uint8_t encoded[sizeof(size_t) + 1];
        size_t encoded_len = {{ p }}_raw_length_encode(ctx->customization_len, encoded);
        {{ p }}_raw_update(ctx, encoded, encoded_len);
        if (ctx->tree) {
            if (ctx->leaf_len != 0) {
                {{ p }}_raw_emit_leaf(ctx);
            }
            encoded_len = {{ p }}_raw_length_encode(ctx->chaining_count, encoded);
            libdecaf_nif_turboshake_absorb(&ctx->root, encoded, encoded_len);
            static const uint8_t trailer[2] = {0xFF, 0xFF};
            libdecaf_nif_turboshake_absorb(&ctx->root, trailer, sizeof(trailer));
        }
        ctx->finalized = true;
    }
    libdecaf_nif_turboshake_squeeze(&ctx->root, output, output_len);
}




{% endmacro %}
