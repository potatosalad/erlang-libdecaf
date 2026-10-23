{% macro lifecycle(f) %}
{% set p=f.prefix %}
static ErlNifResourceType *{{ p }}_resource_type;
static ErlNifResourceType *{{ p }}_absorb_resource_type;
static ErlNifResourceType *{{ p }}_squeeze_resource_type;

/* Continuations own private contexts and retain input only until absorption
 * completes. Published resources are immutable, including their output cursor. */
typedef struct {
    {{ p }}_ctx_t state;
    ErlNifEnv *work_env;
    ERL_NIF_TERM input, elements;
    ErlNifBinary current;
    size_t offset, length;
    unsigned stage;
    bool output, tuple, current_valid, advancing;
} {{ p }}_absorb_trap_t;

typedef struct {
    {{ p }}_ctx_t state;
    ErlNifBinary output;
    size_t offset;
    bool owns_output, advancing;
} {{ p }}_squeeze_trap_t;

static ERL_NIF_TERM {{ p }}_absorb_continue(ErlNifEnv *, int, const ERL_NIF_TERM []);
static ERL_NIF_TERM {{ p }}_squeeze_continue(ErlNifEnv *, int, const ERL_NIF_TERM []);

static void
{{ p }}_state_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    {{ p }}_destroy(obj);
}

static void
{{ p }}_absorb_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    {{ p }}_absorb_trap_t *trap = obj;
    {{ p }}_destroy(&trap->state);
    if (trap->work_env != NULL)
        enif_free_env(trap->work_env);
}

static void
{{ p }}_squeeze_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    {{ p }}_squeeze_trap_t *trap = obj;
    {{ p }}_destroy(&trap->state);
    if (trap->owns_output) {
        decaf_bzero(trap->output.data, trap->output.size);
        enif_release_binary(&trap->output);
    }
}

int
{{ p }}_load(ErlNifEnv *env)
{
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    {{ p }}_resource_type = enif_open_resource_type(env, "libdecaf_nif", "{{ p }}_api_state",
                                                    {{ p }}_state_dtor, flags, NULL);
    {{ p }}_absorb_resource_type = enif_open_resource_type(env, "libdecaf_nif", "{{ p }}_api_absorb",
                                                           {{ p }}_absorb_dtor, flags, NULL);
    {{ p }}_squeeze_resource_type = enif_open_resource_type(env, "libdecaf_nif", "{{ p }}_api_squeeze",
                                                            {{ p }}_squeeze_dtor, flags, NULL);
{% if f.name in ('kt', 'hopmac') %}
    {{ p }}_custom_resource_type = enif_open_resource_type(env, "libdecaf_nif", "{{ p }}_custom",
                                                           {{ p }}_custom_dtor, flags, NULL);
    if ({{ p }}_custom_resource_type == NULL)
        return -1;
{% endif %}
    return {{ p }}_resource_type != NULL && {{ p }}_absorb_resource_type != NULL &&
           {{ p }}_squeeze_resource_type != NULL ? 0 : -1;
}

bool
{{ p }}_accepts(ErlNifEnv *env, ERL_NIF_TERM term, bool hash_mode)
{
    {{ p }}_ctx_t *state;
    return enif_get_resource(env, term, {{ p }}_resource_type, (void **)&state) &&
           state->hash_mode == hash_mode;
}

static void
{{ p }}_consume(ErlNifEnv *env, size_t remaining)
{
    size_t budget = REDUCTIONS_UNTIL_YCF_YIELD();
    if (remaining < budget)
        enif_consume_timeslice(env, (int)((100 * (budget - remaining) + budget - 1) / budget));
}

static ERL_NIF_TERM
{{ p }}_publish(ErlNifEnv *env, const {{ p }}_ctx_t *state)
{
    {{ p }}_ctx_t *resource = enif_alloc_resource({{ p }}_resource_type, sizeof(*resource));
    if (resource == NULL)
        return EXCP_ERROR(env, "Can't allocate {{ f.name }} state");
    {{ p }}_clone(resource, state);
    ERL_NIF_TERM result = enif_make_resource(env, resource);
    enif_release_resource(resource);
    return result;
}

static ERL_NIF_TERM
{{ p }}_squeeze_step(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], size_t remaining)
{
    {{ p }}_squeeze_trap_t *trap;
    if (argc != 1 || !enif_get_resource(env, argv[0], {{ p }}_squeeze_resource_type, (void **)&trap) ||
        !trap->owns_output)
        return enif_make_badarg(env);
    size_t take = trap->output.size - trap->offset;
    if (take > remaining)
        take = remaining;
    {{ p }}_output(&trap->state, trap->output.data + trap->offset, take);
    trap->offset += take;
    remaining -= take;
    if (trap->offset != trap->output.size) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "{{ p }}_squeeze_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 {{ p }}_squeeze_continue, argc, argv);
    }
    ERL_NIF_TERM result;
    if (trap->advancing) {
        ERL_NIF_TERM state = {{ p }}_publish(env, &trap->state);
        if (enif_is_exception(env, state))
            return state;
        result = enif_make_tuple2(env, state, enif_make_binary(env, &trap->output));
    } else {
        result = enif_make_binary(env, &trap->output);
    }
    trap->owns_output = false;
    {{ p }}_destroy(&trap->state);
    {{ p }}_consume(env, remaining);
    return result;
}

static ERL_NIF_TERM
{{ p }}_squeeze_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_squeeze_step(env, argc, argv, REDUCTIONS_UNTIL_YCF_YIELD());
}

static ERL_NIF_TERM
{{ p }}_begin_output(ErlNifEnv *env, const {{ p }}_ctx_t *old, size_t length, bool advancing, size_t remaining)
{
    {{ p }}_squeeze_trap_t *trap = enif_alloc_resource({{ p }}_squeeze_resource_type, sizeof(*trap));
    if (trap == NULL)
        return EXCP_ERROR(env, "Can't allocate {{ f.name }} squeeze continuation");
    decaf_bzero(trap, sizeof(*trap));
    {{ p }}_clone(&trap->state, old);
    if (!{{ p }}_finish(&trap->state)) {
        enif_release_resource(trap);
        return EXCP_BADARG(env, "{{ f.name }} input exceeds its counter limit");
    }
    if (!enif_alloc_binary(length, &trap->output)) {
        enif_release_resource(trap);
        return EXCP_ERROR(env, "Can't allocate output binary");
    }
    trap->owns_output = true;
    trap->advancing = advancing;
    ERL_NIF_TERM args[] = {enif_make_resource(env, trap)};
    enif_release_resource(trap);
    return {{ p }}_squeeze_step(env, 1, args, remaining);
}

static ERL_NIF_TERM
{{ p }}_absorb_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_absorb_trap_t *trap;
    if (argc != 1 || !enif_get_resource(env, argv[0], {{ p }}_absorb_resource_type, (void **)&trap) ||
        trap->work_env == NULL)
        return enif_make_badarg(env);
    size_t remaining = REDUCTIONS_UNTIL_YCF_YIELD();
    while (remaining != 0) {
        if (trap->current_valid && trap->offset < trap->current.size) {
            size_t cost = {{ p }}_input_cost(&trap->state);
            size_t take = trap->current.size - trap->offset;
            if (take > remaining / cost)
                take = remaining / cost;
            if (take == 0)
                break;
            {{ p }}_update(&trap->state, trap->current.data + trap->offset, take);
            trap->offset += take;
            remaining -= take * cost;
            if (trap->offset != trap->current.size)
                break;
        }
        trap->current_valid = false;
        trap->offset = 0;
        if (trap->stage == 0) {
            trap->stage = 1;
{% if f.name == 'tuplehash' %}
            if (trap->tuple) {
                trap->elements = trap->input;
            } else {
                trap->elements = enif_make_list1(trap->work_env, trap->input);
            }
{% else %}
            if (!enif_inspect_iolist_as_binary(trap->work_env, trap->input, &trap->current))
                return EXCP_BADARG(env, "Input must be iodata");
            trap->current_valid = true;
            continue;
{% endif %}
        }
{% if f.name == 'tuplehash' %}
        if (trap->stage == 1) {
            ERL_NIF_TERM element, tail;
            if (enif_get_list_cell(trap->work_env, trap->elements, &element, &tail)) {
                if (remaining < 16)
                    break;
                if (!enif_inspect_iolist_as_binary(trap->work_env, element, &trap->current) ||
                    trap->current.size > SIZE_MAX / 8)
                    return EXCP_BADARG(env, "Each tuple element must be encodable iodata");
                uint8_t encoded[sizeof(size_t) + 1];
                size_t size = {{ p }}_left_encode(trap->current.size * 8, encoded);
                {{ p }}_update(&trap->state, encoded, size);
                trap->elements = tail;
                trap->current_valid = true;
                remaining -= 16;
                continue;
            }
            if (!enif_is_empty_list(trap->work_env, trap->elements))
                return EXCP_BADARG(env, "TupleHash input must be a proper list of elements");
        }
{% endif %}
        if (trap->stage <= 1) {
            trap->stage = 2;
{% if f.name in ('kt', 'hopmac') %}
            if (trap->output && !trap->state.squeezing && trap->state.custom != NULL) {
                trap->current.data = trap->state.custom->data;
                trap->current.size = trap->state.custom->size;
                trap->current_valid = true;
                continue;
            }
{% endif %}
        }
        if (!{{ p }}_valid(&trap->state))
            return EXCP_BADARG(env, "{{ f.name }} input exceeds its counter limit");
        enif_free_env(trap->work_env);
        trap->work_env = NULL;
        ERL_NIF_TERM result = trap->output ?
            {{ p }}_begin_output(env, &trap->state, trap->length, trap->advancing, remaining) :
            {{ p }}_publish(env, &trap->state);
        {{ p }}_destroy(&trap->state);
        if (!trap->output)
            {{ p }}_consume(env, remaining);
        return result;
    }
    BUMP_ALL_REDS(env);
    return enif_schedule_nif(env, "{{ p }}_absorb_continue", ERL_NIF_NORMAL_JOB_BOUND,
                             {{ p }}_absorb_continue, argc, argv);
}

static ERL_NIF_TERM
{{ p }}_run(ErlNifEnv *env, const {{ p }}_ctx_t *state, ERL_NIF_TERM prefix,
             ERL_NIF_TERM input, bool tuple, bool output, bool advancing, size_t length)
{
    {{ p }}_absorb_trap_t *trap = enif_alloc_resource({{ p }}_absorb_resource_type, sizeof(*trap));
    if (trap == NULL)
        return EXCP_ERROR(env, "Can't allocate {{ f.name }} absorb continuation");
    decaf_bzero(trap, sizeof(*trap));
    {{ p }}_clone(&trap->state, state);
    trap->work_env = enif_alloc_env();
    if (trap->work_env == NULL) {
        enif_release_resource(trap);
        return EXCP_ERROR(env, "Can't allocate input environment");
    }
    trap->input = enif_make_copy(trap->work_env, input);
    ERL_NIF_TERM copied_prefix = enif_make_copy(trap->work_env, prefix);
    if (!enif_inspect_iolist_as_binary(trap->work_env, copied_prefix, &trap->current)) {
        enif_release_resource(trap);
        return EXCP_BADARG(env, "Invalid initialization prefix");
    }
    trap->current_valid = true;
    trap->tuple = tuple;
    trap->output = output;
    trap->advancing = advancing;
    trap->length = length;
    ERL_NIF_TERM args[] = {enif_make_resource(env, trap)};
    enif_release_resource(trap);
    return {{ p }}_absorb_continue(env, 1, args);
}

ERL_NIF_TERM
{{ p }}_hash_update(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_ctx_t *state;
    if (argc != 2 || !enif_get_resource(env, argv[0], {{ p }}_resource_type, (void **)&state) || !state->hash_mode)
        return EXCP_BADARG(env, "Expected a hash state");
    return {{ p }}_run(env, state, enif_make_list(env, 0), argv[1], false, false, false, 0);
}

ERL_NIF_TERM
{{ p }}_hash_final(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_ctx_t *state;
    if (argc != 1 || !enif_get_resource(env, argv[0], {{ p }}_resource_type, (void **)&state) || !state->hash_mode)
        return EXCP_BADARG(env, "Expected a hash state");
{% if f.name in ('kt', 'hopmac') %}
    return {{ p }}_run(env, state, enif_make_list(env, 0), enif_make_list(env, 0), false, true, false, state->output_len);
{% else %}
    return {{ p }}_begin_output(env, state, state->output_len, false, REDUCTIONS_UNTIL_YCF_YIELD());
{% endif %}
}
{% if f.xof_algorithms %}
ERL_NIF_TERM
{{ p }}_xof_absorb(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_ctx_t *state;
    if (argc != 2 || !enif_get_resource(env, argv[0], {{ p }}_resource_type, (void **)&state) || state->hash_mode)
        return EXCP_BADARG(env, "Expected an XOF state");
    if (state->squeezing)
        return EXCP_BADARG(env, "Cannot absorb input after squeezing has begun");
    return {{ p }}_run(env, state, enif_make_list(env, 0), argv[1], false, false, false, 0);
}

ERL_NIF_TERM
{{ p }}_xof_squeeze(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_ctx_t *state;
    unsigned long length;
    if (argc != 2 || !enif_get_resource(env, argv[0], {{ p }}_resource_type, (void **)&state) || state->hash_mode)
        return EXCP_BADARG(env, "Expected an XOF state");
    if (!enif_get_ulong(env, argv[1], &length))
        return EXCP_BADARG(env, "Length must be a non-negative byte count");
{% if f.name in ('kt', 'hopmac') %}
    if (!state->squeezing)
        return {{ p }}_run(env, state, enif_make_list(env, 0), enif_make_list(env, 0), false, true, true, length);
{% endif %}
    return {{ p }}_begin_output(env, state, length, true, REDUCTIONS_UNTIL_YCF_YIELD());
}
{% endif %}

{% for fun in f.functions('hash') + f.functions('xof') %}
ERL_NIF_TERM
{{ fun.c_name }}(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != {{ fun.arity }})
        return enif_make_badarg(env);
{% for arg in fun.arguments %}
    ERL_NIF_TERM {{ arg.name }} = argv[{{ loop.index0 }}];
{% endfor %}
    {{ p }}_ctx_t state;
    decaf_bzero(&state, sizeof(state));
    ERL_NIF_TERM prefix;
    int status = {{ p }}_create(env, Type, {{ 'true' if fun.family == 'hash' else 'false' }},
        {{ 'OutputLength' if 'OutputLength' in fun.arguments | map(attribute='name') else '0' }},
        {{ 'true' if 'OutputLength' in fun.arguments | map(attribute='name') else 'false' }},
        {{ 'Key' if 'Key' in fun.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }},
        {{ 'FunctionName' if 'FunctionName' in fun.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }},
        {{ 'CustomizationString' if 'CustomizationString' in fun.arguments | map(attribute='name') else 'enif_make_list(env, 0)' }},
        {{ 'BlockSize' if 'BlockSize' in fun.arguments | map(attribute='name') else 'enif_make_ulong(env, 0)' }},
        {{ 'DomainSeparation' if 'DomainSeparation' in fun.arguments | map(attribute='name') else 'enif_make_ulong(env, 0x1F)' }},
        &state, &prefix);
    if (status != 1) {
        {{ p }}_destroy(&state);
        return status == 0 ? EXCP_BADARG(env, "Invalid {{ f.name }} algorithm, length, or initialization parameters") :
                             EXCP_ERROR(env, "Can't allocate {{ f.name }} initialization data");
    }
    ERL_NIF_TERM result = {{ p }}_run(env, &state, prefix,
        {{ 'Input' if fun.operation == 'once' else 'enif_make_list(env, 0)' }},
        {{ 'true' if f.name == 'tuplehash' else 'false' }}, {{ 'true' if fun.operation == 'once' else 'false' }}, false, state.output_len);
    {{ p }}_destroy(&state);
    return result;
}
{% endfor %}
{% endmacro %}
