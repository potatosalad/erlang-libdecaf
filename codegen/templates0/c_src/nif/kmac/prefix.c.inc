{% macro prefix(p) %}
/* KMAC = cSHAKE(bytepad(encode_string(K), rate) || message || right_encode(L),
 *               N="KMAC", S=customization). Prefix bytes share the message budget. */
static int
{{ p }}_prefix(ErlNifEnv *env, decaf_keccak_sponge_s *state, size_t rate,
              ERL_NIF_TERM key_term, ERL_NIF_TERM custom_term, ERL_NIF_TERM *prefix)
{
    ErlNifBinary key;
    if (!enif_inspect_iolist_as_binary(env, key_term, &key) || key.size > SIZE_MAX / 8)
        return 0;
    ERL_NIF_TERM domain;
    size_t domain_length;
    int status = libdecaf_nif_cshake_init(env, state, rate, enif_make_string(env, "KMAC", ERL_NIF_LATIN1),
                                        custom_term, &domain, &domain_length);
    if (status != 1)
        return status;
    uint8_t encoded_key[2 * (sizeof(size_t) + 1)];
    size_t key_len = libdecaf_nif_sp800185_left_encode(rate, encoded_key);
    key_len += libdecaf_nif_sp800185_left_encode(key.size * 8, encoded_key + key_len);
    size_t padding = (rate - (key_len + key.size % rate) % rate) % rate;
    ERL_NIF_TERM encoded, zeros;
    if (!libdecaf_nif_sp800185_binary(env, encoded_key, key_len, &encoded) ||
        !libdecaf_nif_sp800185_binary(env, NULL, padding, &zeros))
        return -1;
    *prefix = enif_make_list4(env, domain, encoded, key_term, zeros);
    return 1;
}
{% endmacro %}
