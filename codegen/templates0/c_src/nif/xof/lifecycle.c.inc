{% macro lifecycle(p, update, output, destroy, private_state=false, wipe_output=false,
                   streaming=false, absorbing='true', emit_update=true, load_name=none) %}
/* Each family owns its state and continuation resources. No state is shared
 * with a caller while it is being absorbed or squeezed. */
{{ 'static ' if private_state else '' }}ErlNifResourceType *{{ p }}_resource_type = NULL;
static ErlNifResourceType *{{ p }}_absorb_resource_type = NULL;
static ErlNifResourceType *{{ p }}_squeeze_resource_type = NULL;

typedef ERL_NIF_TERM (*{{ p }}_done_t)(ErlNifEnv *, const {{ p }}_ctx_t *, size_t, size_t);
{% if streaming %}
typedef ERL_NIF_TERM (*{{ p }}_emit_t)(ErlNifEnv *, const {{ p }}_ctx_t *, ErlNifBinary *);
{% endif %}

typedef struct {
    {{ p }}_ctx_t state;
    ErlNifEnv *work_env;
    ErlNifBinary input;
    size_t offset;
    size_t output_len;
    {{ p }}_done_t done;
} {{ p }}_absorb_trap_t;

typedef struct {
    {{ p }}_ctx_t state;
    ErlNifBinary output;
    size_t offset;
    bool owns_output;
{% if streaming %}
    {{ p }}_emit_t emit;
{% endif %}
} {{ p }}_squeeze_trap_t;

static ERL_NIF_TERM {{ p }}_absorb_continue(ErlNifEnv *, int, const ERL_NIF_TERM []);
static ERL_NIF_TERM {{ p }}_squeeze_continue(ErlNifEnv *, int, const ERL_NIF_TERM []);

static void
{{ p }}_state_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    {{ destroy }}(({{ p }}_ctx_t *)obj);
}

static void
{{ p }}_absorb_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    {{ p }}_absorb_trap_t *trap = obj;
    {{ destroy }}(&trap->state);
    if (trap->work_env != NULL) {
        enif_free_env(trap->work_env);
    }
}

static void
{{ p }}_squeeze_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    {{ p }}_squeeze_trap_t *trap = obj;
    {{ destroy }}(&trap->state);
    if (trap->owns_output) {
{% if wipe_output %}
        decaf_bzero(trap->output.data, trap->output.size);
{% endif %}
        enif_release_binary(&trap->output);
    }
}

{{ 'static ' if load_name else '' }}int
{{ load_name or p + '_load' }}(ErlNifEnv *env)
{
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    {{ p }}_resource_type = enif_open_resource_type(env, "libdecaf_nif", "{{ p }}_state",
                                                   {{ p }}_state_dtor, flags, NULL);
    {{ p }}_absorb_resource_type = enif_open_resource_type(env, "libdecaf_nif", "{{ p }}_absorb",
                                                          {{ p }}_absorb_dtor, flags, NULL);
    {{ p }}_squeeze_resource_type = enif_open_resource_type(env, "libdecaf_nif", "{{ p }}_squeeze",
                                                           {{ p }}_squeeze_dtor, flags, NULL);
    return {{ p }}_resource_type != NULL && {{ p }}_absorb_resource_type != NULL &&
           {{ p }}_squeeze_resource_type != NULL ? 0 : -1;
}

static void
{{ p }}_consume(ErlNifEnv *env, size_t remaining)
{
    size_t used = REDUCTIONS_UNTIL_YCF_YIELD() - remaining;
    if (used != 0) {
        enif_consume_timeslice(env, (int)((100 * used + REDUCTIONS_UNTIL_YCF_YIELD() - 1) /
                                         REDUCTIONS_UNTIL_YCF_YIELD()));
    }
}

static ERL_NIF_TERM
{{ p }}_make_state(ErlNifEnv *env, const {{ p }}_ctx_t *state, size_t output_len, size_t remaining)
{
    (void)output_len;
    {{ p }}_ctx_t *resource = enif_alloc_resource({{ p }}_resource_type, sizeof(*resource));
    if (resource == NULL) {
        return EXCP_ERROR(env, "Can't allocate {{ p }} state");
    }
    memcpy(resource, state, sizeof(*resource));
    ERL_NIF_TERM term = enif_make_resource(env, resource);
    enif_release_resource(resource);
    {{ p }}_consume(env, remaining);
    return term;
}

/* Absorb a bounded slice, retaining the input environment only while yielding.
 * The completion function either publishes a new state or begins squeezing. */
static ERL_NIF_TERM
{{ p }}_absorb(ErlNifEnv *env, const {{ p }}_ctx_t *old_state, ERL_NIF_TERM input,
                {{ p }}_done_t done, size_t output_len)
{
    ErlNifEnv *work_env = enif_alloc_env();
    if (work_env == NULL) {
        return EXCP_ERROR(env, "Can't allocate {{ p }} input environment");
    }
    ErlNifBinary binary;
    if (!enif_inspect_iolist_as_binary(work_env, enif_make_copy(work_env, input), &binary)) {
        enif_free_env(work_env);
        return EXCP_BADARG(env, "Input must be iodata");
    }
    {{ p }}_ctx_t state = *old_state;
    size_t remaining = REDUCTIONS_UNTIL_YCF_YIELD();
    size_t take = binary.size < remaining ? binary.size : remaining;
    if (take != 0) {
        {{ update }}(&state, binary.data, take);
    }
    remaining -= take;
    if (take == binary.size) {
        enif_free_env(work_env);
        ERL_NIF_TERM result = done(env, &state, output_len, remaining);
        {{ destroy }}(&state);
        return result;
    }
    {{ p }}_absorb_trap_t *trap = enif_alloc_resource({{ p }}_absorb_resource_type, sizeof(*trap));
    if (trap == NULL) {
        {{ destroy }}(&state);
        enif_free_env(work_env);
        return EXCP_ERROR(env, "Can't allocate {{ p }} absorb continuation");
    }
    trap->state = state;
    {{ destroy }}(&state);
    trap->work_env = work_env;
    trap->input = binary;
    trap->offset = take;
    trap->output_len = output_len;
    trap->done = done;
    ERL_NIF_TERM args[] = {enif_make_resource(env, trap)};
    enif_release_resource(trap);
    BUMP_ALL_REDS(env);
    return enif_schedule_nif(env, "{{ p }}_absorb_continue", ERL_NIF_NORMAL_JOB_BOUND,
                             {{ p }}_absorb_continue, 1, args);
}

static ERL_NIF_TERM
{{ p }}_absorb_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_absorb_trap_t *trap;
    if (argc != 1 || !enif_get_resource(env, argv[0], {{ p }}_absorb_resource_type, (void **)&trap) ||
        trap->work_env == NULL) {
        return EXCP_BADARG(env, "Invalid {{ p }} absorb continuation");
    }
    size_t remaining = REDUCTIONS_UNTIL_YCF_YIELD();
    size_t take = trap->input.size - trap->offset;
    if (take > remaining) {
        take = remaining;
    }
    {{ update }}(&trap->state, trap->input.data + trap->offset, take);
    trap->offset += take;
    remaining -= take;
    if (trap->offset != trap->input.size) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "{{ p }}_absorb_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 {{ p }}_absorb_continue, argc, argv);
    }
    enif_free_env(trap->work_env);
    trap->work_env = NULL;
    ERL_NIF_TERM result = trap->done(env, &trap->state, trap->output_len, remaining);
    {{ destroy }}(&trap->state);
    return result;
}

/* Squeeze from a private copy; the published absorbing state remains reusable.
 * Ownership of the output binary moves to the continuation or the Erlang term. */
{% if streaming %}
static ERL_NIF_TERM
{{ p }}_emit_binary(ErlNifEnv *env, const {{ p }}_ctx_t *state, ErlNifBinary *binary)
{
    (void)state;
    return enif_make_binary(env, binary);
}

static ERL_NIF_TERM
{{ p }}_emit_state(ErlNifEnv *env, const {{ p }}_ctx_t *state, ErlNifBinary *binary)
{
    {{ p }}_ctx_t *resource = enif_alloc_resource({{ p }}_resource_type, sizeof(*resource));
    if (resource == NULL) {
{% if wipe_output %}
        decaf_bzero(binary->data, binary->size);
{% endif %}
        enif_release_binary(binary);
        return EXCP_ERROR(env, "Can't allocate {{ p }} squeezing state");
    }
    *resource = *state;
    ERL_NIF_TERM term = enif_make_resource(env, resource);
    enif_release_resource(resource);
    return enif_make_tuple2(env, term, enif_make_binary(env, binary));
}
{% endif %}

static ERL_NIF_TERM
{{ p }}_{{ 'squeeze_to' if streaming else 'squeeze' }}(
    ErlNifEnv *env, const {{ p }}_ctx_t *old_state, size_t output_len, size_t remaining{% if streaming %}, {{ p }}_emit_t emit{% endif %})
{
    ErlNifBinary binary;
    if (!enif_alloc_binary(output_len, &binary)) {
        return EXCP_ERROR(env, "Can't allocate Output binary");
    }
    {{ p }}_ctx_t state = *old_state;
    size_t take = output_len < remaining ? output_len : remaining;
    {{ output }}(&state, binary.data, take);
    remaining -= take;
    if (take == output_len) {
{% if streaming %}
        ERL_NIF_TERM result = emit(env, &state, &binary);
{% endif %}
        {{ destroy }}(&state);
        {{ p }}_consume(env, remaining);
{% if streaming %}
        return result;
{% else %}
        return enif_make_binary(env, &binary);
{% endif %}
    }
    {{ p }}_squeeze_trap_t *trap = enif_alloc_resource({{ p }}_squeeze_resource_type, sizeof(*trap));
    if (trap == NULL) {
        {{ destroy }}(&state);
{% if wipe_output %}
        decaf_bzero(binary.data, binary.size);
{% endif %}
        enif_release_binary(&binary);
        return EXCP_ERROR(env, "Can't allocate {{ p }} squeeze continuation");
    }
    trap->state = state;
    {{ destroy }}(&state);
    trap->output = binary;
    trap->offset = take;
    trap->owns_output = true;
{% if streaming %}
    trap->emit = emit;
{% endif %}
    ERL_NIF_TERM args[] = {enif_make_resource(env, trap)};
    enif_release_resource(trap);
    BUMP_ALL_REDS(env);
    return enif_schedule_nif(env, "{{ p }}_squeeze_continue", ERL_NIF_NORMAL_JOB_BOUND,
                             {{ p }}_squeeze_continue, 1, args);
}

static ERL_NIF_TERM
{{ p }}_squeeze_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_squeeze_trap_t *trap;
    if (argc != 1 || !enif_get_resource(env, argv[0], {{ p }}_squeeze_resource_type, (void **)&trap) ||
        !trap->owns_output) {
        return EXCP_BADARG(env, "Invalid {{ p }} squeeze continuation");
    }
    size_t remaining = REDUCTIONS_UNTIL_YCF_YIELD();
    size_t take = trap->output.size - trap->offset;
    if (take > remaining) {
        take = remaining;
    }
    {{ output }}(&trap->state, trap->output.data + trap->offset, take);
    trap->offset += take;
    remaining -= take;
    if (trap->offset != trap->output.size) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "{{ p }}_squeeze_continue", ERL_NIF_NORMAL_JOB_BOUND,
                                 {{ p }}_squeeze_continue, argc, argv);
    }
{% if streaming %}
    ERL_NIF_TERM result = trap->emit(env, &trap->state, &trap->output);
{% else %}
    ERL_NIF_TERM result = enif_make_binary(env, &trap->output);
{% endif %}
    trap->owns_output = false;
    {{ destroy }}(&trap->state);
    {{ p }}_consume(env, remaining);
    return result;
}

{% if streaming %}
static ERL_NIF_TERM
{{ p }}_squeeze(ErlNifEnv *env, const {{ p }}_ctx_t *state, size_t length, size_t remaining)
{
    return {{ p }}_squeeze_to(env, state, length, remaining, {{ p }}_emit_binary);
}

static ERL_NIF_TERM
{{ p }}_squeeze_state(ErlNifEnv *env, const {{ p }}_ctx_t *state, size_t length, size_t remaining)
{
    return {{ p }}_squeeze_to(env, state, length, remaining, {{ p }}_emit_state);
}

ERL_NIF_TERM
{{ p }}_squeeze_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_ctx_t *state;
    if (argc != 2 || !enif_get_resource(env, argv[0], {{ p }}_resource_type, (void **)&state)) {
        return EXCP_BADARG(env, "State must be a {{ p }} resource");
    }
    unsigned long length;
    if (!enif_get_ulong(env, argv[1], &length)) {
        return EXCP_BADARG(env, "Length must be a non-negative byte count");
    }
    return {{ p }}_squeeze_state(env, state, length, REDUCTIONS_UNTIL_YCF_YIELD());
}
{% endif %}

{% if emit_update %}
ERL_NIF_TERM
{{ p }}_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    {{ p }}_ctx_t *state;
    if (argc != 2 || !enif_get_resource(env, argv[0], {{ p }}_resource_type, (void **)&state)) {
        return EXCP_BADARG(env, "State must be a {{ p }} resource");
    }
    if (!({{ absorbing }})) {
        return EXCP_BADARG(env, "Cannot absorb input after squeezing has begun");
    }
    return {{ p }}_absorb(env, state, argv[1], {{ p }}_make_state, 0);
}
{% if streaming %}

ERL_NIF_TERM
{{ p }}_absorb_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return {{ p }}_update_2(env, argc, argv);
}
{% endif %}
{% endif %}
{% endmacro %}
