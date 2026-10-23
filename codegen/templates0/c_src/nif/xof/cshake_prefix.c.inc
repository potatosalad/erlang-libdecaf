{% macro prefix(p) %}
/* SP 800-185 encodes lengths in bits, with the integer's byte count first. */
/* Build bytepad(encode_string(N) || encode_string(S), rate) as iodata.
 * Return 1 on success, 0 for invalid input, or -1 on allocation failure.
 * The ordinary absorb/update paths handle yielding for large prefixes. */
static int
{{ p }}_prefix(ErlNifEnv *env, size_t rate, ERL_NIF_TERM function_name,
                                   ERL_NIF_TERM customization, ERL_NIF_TERM *prefix, bool *customized)
{
    ErlNifBinary name, custom;
    if (!enif_inspect_iolist_as_binary(env, function_name, &name) ||
        !enif_inspect_iolist_as_binary(env, customization, &custom) ||
        name.size > SIZE_MAX / 8 || custom.size > SIZE_MAX / 8) {
        return 0;
    }
    *customized = name.size != 0 || custom.size != 0;
    if (!*customized) {
        *prefix = enif_make_list(env, 0);
        return 1;
    }
    uint8_t header[2 * (sizeof(size_t) + 1)], encoded_custom[sizeof(size_t) + 1];
    size_t header_len = {{ p }}_left_encode(rate, header);
    header_len += {{ p }}_left_encode(name.size * 8, header + header_len);
    size_t custom_len = {{ p }}_left_encode(custom.size * 8, encoded_custom);
    size_t remainder = (header_len + name.size % rate + custom_len + custom.size % rate) % rate;
    size_t padding_len = (rate - remainder) % rate;
    ERL_NIF_TERM parts[5];
    uint8_t *data = enif_make_new_binary(env, header_len, &parts[0]);
    if (data == NULL) {
        return -1;
    }
    memcpy(data, header, header_len);
    parts[1] = function_name;
    data = enif_make_new_binary(env, custom_len, &parts[2]);
    if (data == NULL) {
        return -1;
    }
    memcpy(data, encoded_custom, custom_len);
    parts[3] = customization;
    data = enif_make_new_binary(env, padding_len, &parts[4]);
    if (padding_len != 0) {
        if (data == NULL) {
            return -1;
        }
        decaf_bzero(data, padding_len);
    }
    *prefix = enif_make_list_from_array(env, parts, 5);
    return 1;
}



{% endmacro %}
