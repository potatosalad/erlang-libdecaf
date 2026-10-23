{% macro prefix(p) %}
/* Build bytepad(encode_string("KMAC") || encode_string(S), rate) followed
 * by bytepad(encode_string(K), rate). The KMAC-owned absorb continuation
 * handles long keys and customization strings with the message's budget.
 * Return 1 on success, 0 for invalid input, -1 for allocation failure. */
static int
{{ p }}_prefix(ErlNifEnv *env, size_t rate, ERL_NIF_TERM key_term,
              ERL_NIF_TERM custom_term, ERL_NIF_TERM *prefix)
{
    ErlNifBinary key, custom;
    if (!enif_inspect_iolist_as_binary(env, key_term, &key) ||
        !enif_inspect_iolist_as_binary(env, custom_term, &custom) ||
        key.size > SIZE_MAX / 8 || custom.size > SIZE_MAX / 8) {
        return 0;
    }
    uint8_t domain[3 * (sizeof(size_t) + 1) + 4], encoded_key[2 * (sizeof(size_t) + 1)];
    size_t domain_len = {{ p }}_left_encode(rate, domain);
    domain_len += {{ p }}_left_encode(4 * 8, domain + domain_len);
    memcpy(domain + domain_len, "KMAC", 4);
    domain_len += 4;
    domain_len += {{ p }}_left_encode(custom.size * 8, domain + domain_len);
    size_t key_len = {{ p }}_left_encode(rate, encoded_key);
    key_len += {{ p }}_left_encode(key.size * 8, encoded_key + key_len);
    size_t domain_padding = (rate - (domain_len + custom.size % rate) % rate) % rate;
    size_t key_padding = (rate - (key_len + key.size % rate) % rate) % rate;
    ERL_NIF_TERM parts[6];
    if (!{{ p }}_binary(env, domain, domain_len, &parts[0]) ||
        !{{ p }}_binary(env, NULL, domain_padding, &parts[2]) ||
        !{{ p }}_binary(env, encoded_key, key_len, &parts[3]) ||
        !{{ p }}_binary(env, NULL, key_padding, &parts[5])) {
        return -1;
    }
    parts[1] = custom_term;
    parts[4] = key_term;
    *prefix = enif_make_list_from_array(env, parts, 6);
    return 1;
}


{% endmacro %}
