{% macro framing(p, right=true, domain=true, binary=true) %}
static size_t
{{ p }}_left_encode(size_t value, uint8_t *encoded)
{
    size_t bytes = 1;
    for (size_t remaining = value; (remaining >>= 8) != 0; bytes++) {
    }
    encoded[0] = (uint8_t)bytes;
    for (size_t i = 0; i < bytes; i++)
        encoded[bytes - i] = (uint8_t)(value >> (8 * i));
    return bytes + 1;
}

{% if right %}
static size_t
{{ p }}_right_encode(size_t value, uint8_t *encoded)
{
    size_t bytes = {{ p }}_left_encode(value, encoded) - 1;
    memmove(encoded, encoded + 1, bytes);
    encoded[bytes] = (uint8_t)bytes;
    return bytes + 1;
}
{% endif %}

{% if binary %}
static bool
{{ p }}_binary(ErlNifEnv *env, const uint8_t *input, size_t length, ERL_NIF_TERM *term)
{
    uint8_t *data = enif_make_new_binary(env, length, term);
    if (length != 0) {
        if (data == NULL)
            return false;
        if (input != NULL)
            memcpy(data, input, length);
        else
            decaf_bzero(data, length);
    }
    return true;
}

{% endif %}
{% if domain %}
/* bytepad(encode_string(N) || encode_string(S), rate), retaining caller
 * strings as iodata until the component's bounded absorb path consumes them.
 * Internal function names are at most 12 bytes ("ParallelHash"). */
static int
{{ p }}_domain_prefix(ErlNifEnv *env, size_t rate, const char *name, size_t name_len,
                     ERL_NIF_TERM customization, ERL_NIF_TERM *prefix, size_t *prefix_len)
{
    ErlNifBinary custom;
    if (!enif_inspect_iolist_as_binary(env, customization, &custom) || custom.size > SIZE_MAX / 8)
        return 0;
    uint8_t header[3 * (sizeof(size_t) + 1) + 12];
    size_t length = {{ p }}_left_encode(rate, header);
    length += {{ p }}_left_encode(name_len * 8, header + length);
    memcpy(header + length, name, name_len);
    length += name_len;
    length += {{ p }}_left_encode(custom.size * 8, header + length);
    size_t padding = (rate - (length + custom.size % rate) % rate) % rate;
    ERL_NIF_TERM parts[3];
    if (!{{ p }}_binary(env, header, length, &parts[0]) ||
        !{{ p }}_binary(env, NULL, padding, &parts[2]))
        return -1;
    parts[1] = customization;
    *prefix = enif_make_list_from_array(env, parts, 3);
    *prefix_len = length + custom.size + padding;
    return 1;
}
{% endif %}
{% endmacro %}
