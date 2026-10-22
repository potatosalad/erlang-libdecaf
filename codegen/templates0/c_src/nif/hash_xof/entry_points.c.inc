{% macro entry_points(p, group, destroy) %}

ERL_NIF_TERM
{{ p }}_init_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_ctx_t state;
    if (argc != 1 || !{{ p }}_select(env, argv[0], &state)) {
        return EXCP_BADARG(env, "Algorithm must belong to {{ group }}");
    }
    ERL_NIF_TERM result = {{ p }}_make_state(env, &state, 0, REDUCTIONS_UNTIL_YCF_YIELD());
    {{ destroy }}(&state);
    return result;
}

ERL_NIF_TERM
{{ p }}_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    unsigned long output_len;
    if (argc != 3 || !enif_get_ulong(env, argv[2], &output_len)) {
        return EXCP_BADARG(env, "OutputLen must be a non-negative integer");
    }
    {{ p }}_ctx_t state;
    if (!{{ p }}_select(env, argv[0], &state)) {
        return EXCP_BADARG(env, "Algorithm must belong to {{ group }}");
    }
    ERL_NIF_TERM result = {{ p }}_absorb(env, &state, argv[1], {{ p }}_squeeze, output_len);
    {{ destroy }}(&state);
    return result;
}

ERL_NIF_TERM
{{ p }}_final_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_ctx_t *state;
    if (argc != 2 || !enif_get_resource(env, argv[0], {{ p }}_resource_type, (void **)&state)) {
        return EXCP_BADARG(env, "State must be a {{ group }} resource");
    }
    unsigned long output_len;
    if (!enif_get_ulong(env, argv[1], &output_len)) {
        return EXCP_BADARG(env, "OutputLen must be a non-negative integer");
    }
    return {{ p }}_squeeze(env, state, output_len, REDUCTIONS_UNTIL_YCF_YIELD());
}
{% endmacro %}
