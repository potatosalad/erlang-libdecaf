{% macro body(f, a, function, mode, parallel=false) %}
{% set p=f.prefix %}
    if (argc != {{ function.arity }})
        return enif_make_badarg(env);
{% for arg in function.arguments %}
    ERL_NIF_TERM {{ arg.name }} = argv[{{ loop.index0 }}];
{% endfor %}
{% if mode == 'hash' or function.operation == 'once' %}
    size_t length = {{ a.profile.default if mode == 'hash' else 0 }};
{% endif %}
{% if 'OutputLength' in function.arguments | map(attribute='name') %}
    if (!libdecaf_nif_{{ mode }}_length(env, OutputLength, &{{ a.symbol }}_{{ mode }}_algorithm, &length))
        return EXCP_BADARG(env, "Invalid {{ a.name }} output byte length");
{% endif %}
    libdecaf_nif_{{ mode }}_state_t *resource = libdecaf_nif_{{ mode }}_alloc(env, &{{ a.symbol }}_{{ mode }}_algorithm{{ ', length' if mode == 'hash' else '' }});
    if (resource == NULL)
        return EXCP_ERROR(env, "Can't allocate {{ a.name }} {{ mode }} context");
    {{ p }}_ctx_t *state = libdecaf_nif_{{ mode }}_context(resource);
    ERL_NIF_TERM prefix = enif_make_list(env, 0);
    int status = {{ p }}_create({% if f.name != 'sha2' %}env, {% endif %}state{% if f.name != 'sha2' %}, {{ a.profile.rate }}{% endif %}{% if f.name in ('sha3', 'keccak') %}, {{ a.profile.pad }}{% elif f.name == 'turboshake' %}, {{ 'DomainSeparation' if 'DomainSeparation' in function.arguments | map(attribute='name') else 'enif_make_uint(env, 0x1F)' }}{% elif f.name == 'cshake' %}, {{ 'FunctionName' if 'FunctionName' in function.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }}, {{ 'CustomizationString' if 'CustomizationString' in function.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }}, &prefix{% elif f.name in ('hopmac', 'kmac') %}, Key, {{ 'CustomizationString' if 'CustomizationString' in function.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }}, &prefix{% elif f.name == 'parallelhash' %}, BlockSize, {{ 'CustomizationString' if 'CustomizationString' in function.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }}, &prefix{% elif f.name == 'tuplehash' %}, {{ 'CustomizationString' if 'CustomizationString' in function.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }}, &prefix{% elif f.name == 'kt' %}, {{ 'CustomizationString' if 'CustomizationString' in function.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }}{% endif %});
    if (status != 1) {
        enif_release_resource(resource);
        return status == 0 ? EXCP_BADARG(env, "Invalid {{ f.name }} initialization parameters") :
                             EXCP_ERROR(env, "Can't allocate {{ f.name }} initialization data");
    }
{% if parallel %}
    ErlNifBinary prefix_binary;
    if (!enif_inspect_iolist_as_binary(env, prefix, &prefix_binary)) {
        enif_release_resource(resource);
        return EXCP_BADARG(env, "Invalid initialization prefix");
    }
    {{ p }}_update(state, prefix_binary.data, prefix_binary.size);
    ERL_NIF_TERM result = enif_make_resource(env, resource);
    enif_release_resource(resource);
    return result;
{% else %}
    return libdecaf_nif_{{ mode }}_run(env, resource, prefix,
        {{ 'Input' if function.operation == 'once' else 'enif_make_list(env, 0)' }},
        LIBDECAF_NIF_{{ mode | upper }}_INPUT_{{ 'TUPLE' if f.name == 'tuplehash' and function.operation == 'once' else 'DATA' if function.operation == 'once' else 'NONE' }},
        {{ 'true' if function.operation == 'once' else 'false' }}{% if mode == 'xof' %}, false, {{ 'length' if function.operation == 'once' else '0' }}{% endif %});
{% endif %}
{% endmacro %}

{% macro entry_points(f, a) %}
{% set p=f.prefix %}
{% for mode in ('hash', 'xof') %}
{% for function in a.functions(mode, 'once') %}
static ERL_NIF_TERM
{{ a.symbol }}_{{ mode }}_compute_{{ function.arity }}(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
{{ body(f, a, function, mode) }}
}
{% endfor %}
{% endfor %}
{% for function in a.exports %}
ERL_NIF_TERM
{{ function.c_name }}(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
{% if function.operation == 'once' %}
    return {{ a.symbol }}_{{ function.family }}_compute_{{ function.arity }}(env, argc, argv);
{% else %}
{{ body(f, a, function, function.family) }}
{% endif %}
}
{% endfor %}

{% for mode in ('hash', 'xof') %}
{% if a.functions(mode, 'init') %}
{% for operation in ('init', 'once') %}
static ERL_NIF_TERM
{{ a.symbol }}_{{ mode }}_{{ operation }}_entry(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    switch (argc) {
{% for function in a.functions(mode, operation) %}
    case {{ function.arity }}:
        return {{ function.c_name if operation == 'init' else a.symbol + '_' + mode + '_compute_' + function.arity | string }}(env, argc, argv);
{% endfor %}
    default:
        return EXCP_BADARG(env, "Invalid number of {{ a.name }} {{ mode }} parameters");
    }
}
{% endfor %}

{% if f.name in ('kt', 'hopmac', 'parallelhash') %}
{% for function in a.functions(mode, 'init') %}
static ERL_NIF_TERM
{{ a.symbol }}_parallel_{{ mode }}_init_{{ function.arity }}(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
{{ body(f, a, function, mode, true) }}
}
{% endfor %}
static ERL_NIF_TERM
{{ a.symbol }}_parallel_{{ mode }}_init_entry(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    switch (argc) {
{% for function in a.functions(mode, 'init') %}
    case {{ function.arity }}:
        return {{ a.symbol }}_parallel_{{ mode }}_init_{{ function.arity }}(env, argc, argv);
{% endfor %}
    default:
        return EXCP_BADARG(env, "Invalid parallel initialization parameters");
    }
}
{% endif %}
const libdecaf_nif_{{ mode }}_algorithm_t {{ a.symbol }}_{{ mode }}_algorithm = {
    .name = "{{ a.name }}",
    .context_size = sizeof({{ p }}_ctx_t),
    .context_alignment = _Alignof({{ p }}_ctx_t),
{% if mode == 'hash' %}
    .default_output_len = {{ a.profile.default }},
    .length_bound = {{ 'true' if f.name in ('kmac', 'tuplehash', 'parallelhash') else 'false' }},
{% endif %}
    .max_output_len = {{ a.profile.maximum if a.profile.maximum is not none else 'SIZE_MAX' }},
    .clone = {{ p }}_clone,
    .destroy = {{ p }}_destroy,
    .{{ 'update' if mode == 'hash' else 'absorb' }} = {{ p }}_update,
    .{{ 'output' if mode == 'hash' else 'squeeze' }} = {{ p }}_output,
    .finish = {{ p }}_{{ mode }}_finish,
    .valid = {{ p }}_valid,
    .input_cost = {{ p }}_input_cost,
    .element = {{ p + '_element' if f.name == 'tuplehash' else 'NULL' }},
    .suffix = {{ p + '_suffix' if f.name in ('kt', 'hopmac') else 'NULL' }},
    .init = {{ a.symbol }}_{{ mode }}_init_entry,
    .compute = {{ a.symbol }}_{{ mode }}_once_entry,
{% if f.name in ('kt', 'hopmac', 'parallelhash') %}
    .parallel_init = {{ a.symbol }}_parallel_{{ mode }}_init_entry,
    .parallel = &{{ p }}_parallel_algorithm,
{% endif %}
};
{% endif %}
{% endfor %}
{% endmacro %}
