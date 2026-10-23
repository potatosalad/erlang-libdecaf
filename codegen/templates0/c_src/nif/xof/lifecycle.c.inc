/* Atom tags stay stable across code upgrades, including when the generated
 * registry changes order. Context bytes are private to the owning component. */
struct libdecaf_nif_xof_state_s {
    ERL_NIF_TERM algorithm;
    size_t context_size;
    bool squeezing;
    uint8_t *context;
};

/* XOF contexts and continuations are owned by this lifecycle. Published
 * states are immutable; continuations retain private copies. */
static ErlNifResourceType *libdecaf_nif_xof_resource_type;
static ErlNifResourceType *libdecaf_nif_xof_absorb_resource_type;
static ErlNifResourceType *libdecaf_nif_xof_squeeze_resource_type;

typedef struct {
    libdecaf_nif_xof_state_t *state;
    ErlNifEnv *work_env;
    ERL_NIF_TERM input, elements;
    ErlNifBinary current;
    size_t offset, length;
    unsigned stage;
    libdecaf_nif_xof_input_t kind;
    bool output, advancing, current_valid;
} libdecaf_nif_xof_absorb_trap_t;

typedef struct {
    libdecaf_nif_xof_state_t *state;
    ErlNifBinary output;
    size_t offset;
    bool advancing, owns_output;
} libdecaf_nif_xof_squeeze_trap_t;

static ERL_NIF_TERM libdecaf_nif_xof_absorb_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libdecaf_nif_xof_squeeze_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

static void
libdecaf_nif_xof_state_dtor(ErlNifEnv *env, void *object)
{
    libdecaf_nif_xof_state_t *state = object;
    const libdecaf_nif_xof_algorithm_t *algorithm = libdecaf_nif_xof_lookup(env, state->algorithm);
    if (algorithm != NULL && algorithm->context_size == state->context_size)
        algorithm->destroy(state->context);
    decaf_bzero(state, enif_sizeof_resource(state));
}

static void
libdecaf_nif_xof_absorb_dtor(ErlNifEnv *env, void *object)
{
    (void)env;
    libdecaf_nif_xof_absorb_trap_t *trap = object;
    if (trap->state != NULL)
        enif_release_resource(trap->state);
    if (trap->work_env != NULL)
        enif_free_env(trap->work_env);
}

static void
libdecaf_nif_xof_squeeze_dtor(ErlNifEnv *env, void *object)
{
    (void)env;
    libdecaf_nif_xof_squeeze_trap_t *trap = object;
    if (trap->state != NULL)
        enif_release_resource(trap->state);
    if (trap->owns_output) {
        decaf_bzero(trap->output.data, trap->output.size);
        enif_release_binary(&trap->output);
    }
}

int
libdecaf_nif_xof_load(ErlNifEnv *env)
{
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    libdecaf_nif_xof_resource_type = enif_open_resource_type(env, "libdecaf_nif", "xof_context",
        libdecaf_nif_xof_state_dtor, flags, NULL);
    libdecaf_nif_xof_absorb_resource_type = enif_open_resource_type(env, "libdecaf_nif", "xof_absorb",
        libdecaf_nif_xof_absorb_dtor, flags, NULL);
    libdecaf_nif_xof_squeeze_resource_type = enif_open_resource_type(env, "libdecaf_nif", "xof_squeeze",
        libdecaf_nif_xof_squeeze_dtor, flags, NULL);
    return libdecaf_nif_xof_resource_type != NULL && libdecaf_nif_xof_absorb_resource_type != NULL &&
           libdecaf_nif_xof_squeeze_resource_type != NULL ? 0 : -1;
}

libdecaf_nif_xof_state_t *
libdecaf_nif_xof_alloc(ErlNifEnv *env, const libdecaf_nif_xof_algorithm_t *algorithm)
{
    /* The NIF resource header may be only word-aligned. Align the private
     * context inside its allocation rather than imposing alignment on it. */
    size_t alignment = algorithm->context_alignment;
    size_t allocation_size = sizeof(libdecaf_nif_xof_state_t) + algorithm->context_size + alignment - 1;
    libdecaf_nif_xof_state_t *state = enif_alloc_resource(libdecaf_nif_xof_resource_type, allocation_size);
    if (state != NULL) {
        decaf_bzero(state, allocation_size);
        uintptr_t start = (uintptr_t)(state + 1);
        state->context = (uint8_t *)(start + (alignment - start % alignment) % alignment);
        state->algorithm = enif_make_atom(env, algorithm->name);
        state->context_size = algorithm->context_size;
    }
    return state;
}

void *
libdecaf_nif_xof_context(libdecaf_nif_xof_state_t *state)
{
    return state->context;
}

bool
libdecaf_nif_xof_length(ErlNifEnv *env, ERL_NIF_TERM term, const libdecaf_nif_xof_algorithm_t *algorithm,
                         size_t *length)
{
    unsigned long value;
    if (!enif_get_ulong(env, term, &value) || value > algorithm->max_output_len)
        return false;
    *length = value;
    return true;
}

static libdecaf_nif_xof_state_t *
libdecaf_nif_xof_get(ErlNifEnv *env, ERL_NIF_TERM term,
                     const libdecaf_nif_xof_algorithm_t **algorithm)
{
    libdecaf_nif_xof_state_t *state;
    if (!enif_get_resource(env, term, libdecaf_nif_xof_resource_type, (void **)&state) ||
        (*algorithm = libdecaf_nif_xof_lookup(env, state->algorithm)) == NULL ||
        state->context_size != (*algorithm)->context_size)
        return NULL;
    return state;
}

static libdecaf_nif_xof_state_t *
libdecaf_nif_xof_clone(ErlNifEnv *env, const libdecaf_nif_xof_state_t *state,
                       const libdecaf_nif_xof_algorithm_t *algorithm)
{
    libdecaf_nif_xof_state_t *copy = libdecaf_nif_xof_alloc(env, algorithm);
    if (copy != NULL) {
        copy->squeezing = state->squeezing;
        algorithm->clone(copy->context, state->context);
    }
    return copy;
}

static void
libdecaf_nif_xof_consume(ErlNifEnv *env, size_t remaining)
{
    size_t budget = REDUCTIONS_UNTIL_YCF_YIELD();
    if (remaining < budget)
        enif_consume_timeslice(env, (int)((100 * (budget - remaining) + budget - 1) / budget));
}

static ERL_NIF_TERM
libdecaf_nif_xof_squeeze_step(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], size_t remaining)
{
    libdecaf_nif_xof_squeeze_trap_t *trap;
    if (argc != 1 || !enif_get_resource(env, argv[0], libdecaf_nif_xof_squeeze_resource_type, (void **)&trap) ||
        trap->state == NULL || !trap->owns_output)
        return enif_make_badarg(env);
    const libdecaf_nif_xof_algorithm_t *algorithm = libdecaf_nif_xof_lookup(env, trap->state->algorithm);
    if (algorithm == NULL)
        return EXCP_BADARG(env, "Unknown algorithm in squeeze continuation");
    size_t take = trap->output.size - trap->offset;
    if (take > remaining)
        take = remaining;
    algorithm->squeeze(trap->state->context, trap->output.data + trap->offset, take);
    trap->offset += take;
    remaining -= take;
    if (trap->offset != trap->output.size) {
        BUMP_ALL_REDS(env);
        return enif_schedule_nif(env, "libdecaf_nif_xof_squeeze_continue", ERL_NIF_NORMAL_JOB_BOUND,
            libdecaf_nif_xof_squeeze_continue, argc, argv);
    }
    ERL_NIF_TERM binary = enif_make_binary(env, &trap->output);
    trap->owns_output = false;
    ERL_NIF_TERM result = trap->advancing ?
        enif_make_tuple2(env, enif_make_resource(env, trap->state), binary) : binary;
    enif_release_resource(trap->state);
    trap->state = NULL;
    libdecaf_nif_xof_consume(env, remaining);
    return result;
}

static ERL_NIF_TERM
libdecaf_nif_xof_squeeze_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    return libdecaf_nif_xof_squeeze_step(env, argc, argv, REDUCTIONS_UNTIL_YCF_YIELD());
}

/* Takes the private state's reference, including on allocation failure. */
static ERL_NIF_TERM
libdecaf_nif_xof_begin_output(ErlNifEnv *env, libdecaf_nif_xof_state_t *state,
                               size_t length, bool advancing, size_t remaining)
{
    const libdecaf_nif_xof_algorithm_t *algorithm = libdecaf_nif_xof_lookup(env, state->algorithm);
    if (algorithm == NULL || (!state->squeezing && !algorithm->finish(state->context))) {
        enif_release_resource(state);
        return EXCP_BADARG(env, "Input exceeds the algorithm's counter limit");
    }
    state->squeezing = true;
    libdecaf_nif_xof_squeeze_trap_t *trap = enif_alloc_resource(libdecaf_nif_xof_squeeze_resource_type, sizeof(*trap));
    if (trap == NULL) {
        enif_release_resource(state);
        return EXCP_ERROR(env, "Can't allocate squeeze continuation");
    }
    decaf_bzero(trap, sizeof(*trap));
    trap->state = state;
    if (!enif_alloc_binary(length, &trap->output)) {
        enif_release_resource(trap);
        return EXCP_ERROR(env, "Can't allocate output binary");
    }
    trap->owns_output = true;
    trap->advancing = advancing;
    ERL_NIF_TERM args[] = {enif_make_resource(env, trap)};
    enif_release_resource(trap);
    return libdecaf_nif_xof_squeeze_step(env, 1, args, remaining);
}

static ERL_NIF_TERM
libdecaf_nif_xof_absorb_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_xof_absorb_trap_t *trap;
    if (argc != 1 || !enif_get_resource(env, argv[0], libdecaf_nif_xof_absorb_resource_type, (void **)&trap) ||
        trap->state == NULL || trap->work_env == NULL)
        return enif_make_badarg(env);
    libdecaf_nif_xof_state_t *state = trap->state;
    const libdecaf_nif_xof_algorithm_t *algorithm = libdecaf_nif_xof_lookup(env, state->algorithm);
    if (algorithm == NULL)
        return EXCP_BADARG(env, "Unknown algorithm in absorb continuation");
    size_t remaining = REDUCTIONS_UNTIL_YCF_YIELD();
    while (remaining != 0) {
        if (trap->current_valid && trap->offset < trap->current.size) {
            size_t cost = algorithm->input_cost(state->context);
            size_t take = trap->current.size - trap->offset;
            if (take > remaining / cost)
                take = remaining / cost;
            if (take == 0)
                break;
            algorithm->absorb(state->context, trap->current.data + trap->offset, take);
            trap->offset += take;
            remaining -= take * cost;
            if (trap->offset != trap->current.size)
                break;
        }
        trap->current_valid = false;
        trap->offset = 0;
        if (trap->stage == 0) {
            trap->stage = 1;
            if (trap->kind == LIBDECAF_NIF_XOF_INPUT_NONE) {
                trap->stage = 2;
            } else if (trap->kind == LIBDECAF_NIF_XOF_INPUT_DATA) {
                if (!enif_inspect_iolist_as_binary(trap->work_env, trap->input, &trap->current))
                    return EXCP_BADARG(env, "Input must be iodata");
                trap->current_valid = true;
                trap->stage = 2;
                continue;
            }
        }
        if (trap->stage == 1) {
            ERL_NIF_TERM element, tail;
            if (enif_get_list_cell(trap->work_env, trap->elements, &element, &tail)) {
                if (remaining < 16)
                    break;
                if (!enif_inspect_iolist_as_binary(trap->work_env, element, &trap->current) ||
                    trap->current.size > SIZE_MAX / 8)
                    return EXCP_BADARG(env, "Each tuple element must be encodable iodata");
                algorithm->element(state->context, trap->current.size);
                trap->elements = tail;
                trap->current_valid = true;
                remaining -= 16;
                continue;
            }
            if (!enif_is_empty_list(trap->work_env, trap->elements))
                return EXCP_BADARG(env, "TupleHash input must be a proper list of elements");
            trap->stage = 2;
        }
        if (trap->stage == 2) {
            trap->stage = 3;
            if (trap->output && !state->squeezing && algorithm->suffix != NULL) {
                const uint8_t *data;
                algorithm->suffix(state->context, &data, &trap->current.size);
                trap->current.data = (uint8_t *)data;
                trap->current_valid = true;
                continue;
            }
        }
        if (!algorithm->valid(state->context))
            return EXCP_BADARG(env, "Input exceeds the algorithm's counter limit");
        enif_free_env(trap->work_env);
        trap->work_env = NULL;
        trap->state = NULL;
        if (trap->output)
            return libdecaf_nif_xof_begin_output(env, state, trap->length, trap->advancing, remaining);
        ERL_NIF_TERM result = enif_make_resource(env, state);
        enif_release_resource(state);
        libdecaf_nif_xof_consume(env, remaining);
        return result;
    }
    BUMP_ALL_REDS(env);
    return enif_schedule_nif(env, "libdecaf_nif_xof_absorb_continue", ERL_NIF_NORMAL_JOB_BOUND,
        libdecaf_nif_xof_absorb_continue, argc, argv);
}

ERL_NIF_TERM
libdecaf_nif_xof_run(ErlNifEnv *env, libdecaf_nif_xof_state_t *state, ERL_NIF_TERM prefix, ERL_NIF_TERM input,
                     libdecaf_nif_xof_input_t kind, bool output, bool advancing, size_t length)
{
    libdecaf_nif_xof_absorb_trap_t *trap = enif_alloc_resource(libdecaf_nif_xof_absorb_resource_type, sizeof(*trap));
    if (trap == NULL) {
        enif_release_resource(state);
        return EXCP_ERROR(env, "Can't allocate absorb continuation");
    }
    decaf_bzero(trap, sizeof(*trap));
    trap->state = state;
    trap->kind = kind;
    trap->output = output;
    trap->advancing = advancing;
    trap->length = length;
    trap->work_env = enif_alloc_env();
    if (trap->work_env == NULL) {
        enif_release_resource(trap);
        return EXCP_ERROR(env, "Can't allocate input environment");
    }
    trap->input = enif_make_copy(trap->work_env, input);
    trap->elements = kind == LIBDECAF_NIF_XOF_INPUT_ELEMENT ?
        enif_make_list1(trap->work_env, trap->input) : trap->input;
    ERL_NIF_TERM copied_prefix = enif_make_copy(trap->work_env, prefix);
    if (!enif_inspect_iolist_as_binary(trap->work_env, copied_prefix, &trap->current)) {
        enif_release_resource(trap);
        return EXCP_BADARG(env, "Invalid initialization prefix");
    }
    trap->current_valid = true;
    ERL_NIF_TERM args[] = {enif_make_resource(env, trap)};
    enif_release_resource(trap);
    return libdecaf_nif_xof_absorb_continue(env, 1, args);
}
