static ERL_NIF_TERM
libdecaf_nif_parallel_xof_progress(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation)
{
    ERL_NIF_TERM state_term = libdecaf_nif_parallel_operation_state(env, operation);
    const libdecaf_nif_xof_algorithm_t *algorithm;
    libdecaf_nif_xof_state_t *state = libdecaf_nif_xof_get(env, state_term, &algorithm);
    if (state == NULL || algorithm->parallel == NULL) {
        libdecaf_nif_parallel_operation_abort(env, operation);
        return EXCP_BADARG(env, "Expected a parallel XOF operation");
    }
    if (enif_thread_type() == ERL_NIF_THR_NORMAL_SCHEDULER && algorithm->parallel->block_size(state->context) > 8192) {
        ERL_NIF_TERM argument = enif_make_resource(env, operation);
        return enif_schedule_nif(env, "parallel_xof_continue", ERL_NIF_DIRTY_JOB_CPU_BOUND,
                                   libdecaf_nif_parallel_xof_continue_1, 1, &argument);
    }
    int status = libdecaf_nif_parallel_operation_step(env, operation, state->context, algorithm->parallel);
    if (status < 0 || !algorithm->valid(state->context)) {
        libdecaf_nif_parallel_operation_abort(env, operation);
        return EXCP_BADARG(env, "Parallel XOF context overflow or cancellation");
    }
    if (status == 2 || status == 3) {
        ERL_NIF_TERM argument = enif_make_resource(env, operation);
        int flags = status == 3 || enif_thread_type() != ERL_NIF_THR_NORMAL_SCHEDULER ? ERL_NIF_DIRTY_JOB_CPU_BOUND : ERL_NIF_NORMAL_JOB_BOUND;
        return enif_schedule_nif(env, "parallel_xof_continue", flags,
                                   libdecaf_nif_parallel_xof_continue_1, 1, &argument);
    }
    if (status == 0)
        return libdecaf_nif_parallel_operation_await(env, operation);
    return libdecaf_nif_parallel_operation_result(env, operation, state_term);
}

ERL_NIF_TERM
libdecaf_nif_parallel_xof_init_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_xof_parameters_t parameters;
    if (argc != 1 || !libdecaf_nif_xof_parameters(env, argv[0], &parameters) || parameters.algorithm->parallel == NULL)
        return EXCP_BADARG(env, "Expected parallel-capable XOF parameters");
    return parameters.algorithm->parallel_init(env, parameters.argc, parameters.argv);
}

static ERL_NIF_TERM
libdecaf_nif_parallel_xof_begin(ErlNifEnv *env, ERL_NIF_TERM old_term, ERL_NIF_TERM input, bool finish, size_t output_length)
{
    const libdecaf_nif_xof_algorithm_t *algorithm;
    libdecaf_nif_xof_state_t *old = libdecaf_nif_xof_get(env, old_term, &algorithm);
    if (old == NULL || algorithm->parallel == NULL || old->squeezing)
        return EXCP_BADARG(env, "Expected a parallel XOF state");
    libdecaf_nif_xof_state_t *state = libdecaf_nif_xof_clone(env, old, algorithm);
    if (state == NULL)
        return EXCP_ERROR(env, "Can't allocate parallel XOF context");
    ERL_NIF_TERM state_term = enif_make_resource(env, state), error;
    enif_release_resource(state);
    libdecaf_nif_parallel_operation_t *operation = libdecaf_nif_parallel_operation_create(env,
        libdecaf_nif_parallel_xof_resource_type, state_term, input, algorithm->parallel->block_size(state->context),
        algorithm->parallel->leaf(state->context), finish, output_length, &error);
    if (operation == NULL)
        return error;
    ERL_NIF_TERM result = libdecaf_nif_parallel_xof_progress(env, operation);
    enif_release_resource(operation);
    return result;
}

ERL_NIF_TERM
libdecaf_nif_parallel_xof_absorb_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2)
        return enif_make_badarg(env);
    return libdecaf_nif_parallel_xof_begin(env, argv[0], argv[1], false, 0);
}

ERL_NIF_TERM
libdecaf_nif_parallel_xof_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    size_t output_length;
    unsigned long length;
    if (argc != 3 || !enif_get_ulong(env, argv[2], &length))
        return EXCP_BADARG(env, "Expected a non-negative output byte length");
    output_length = length;
    ERL_NIF_TERM state = libdecaf_nif_parallel_xof_init_1(env, 1, argv);
    if (enif_is_exception(env, state))
        return state;
    return libdecaf_nif_parallel_xof_begin(env, state, argv[1], true, output_length);
}

ERL_NIF_TERM
libdecaf_nif_parallel_xof_continue_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_parallel_operation_t *operation;
    if (argc != 1 || (operation = libdecaf_nif_parallel_operation_get(env,
        libdecaf_nif_parallel_xof_resource_type, argv[0])) == NULL)
        return EXCP_BADARG(env, "Expected an owned pending parallel XOF operation");
    return libdecaf_nif_parallel_xof_progress(env, operation);
}

ERL_NIF_TERM
libdecaf_nif_parallel_xof_squeeze_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    const libdecaf_nif_xof_algorithm_t *algorithm;
    if (argc != 2 || libdecaf_nif_xof_get(env, argv[0], &algorithm) == NULL || algorithm->parallel == NULL)
        return EXCP_BADARG(env, "Expected a parallel XOF state");
    return libdecaf_nif_xof_squeeze_2(env, argc, argv);
}
