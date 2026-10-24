static ERL_NIF_TERM
libdecaf_nif_parallel_hash_progress(ErlNifEnv *env, libdecaf_nif_parallel_operation_t *operation)
{
    ERL_NIF_TERM state_term = libdecaf_nif_parallel_operation_state(env, operation);
    const libdecaf_nif_hash_algorithm_t *algorithm;
    libdecaf_nif_hash_state_t *state = libdecaf_nif_hash_get(env, state_term, &algorithm);
    if (state == NULL || algorithm->parallel == NULL) {
        libdecaf_nif_parallel_operation_abort(env, operation);
        return EXCP_BADARG(env, "Expected a parallel Hash operation");
    }
    int status = libdecaf_nif_parallel_operation_step(env, operation, state->context, algorithm->parallel);
    if (status < 0 || !algorithm->valid(state->context)) {
        libdecaf_nif_parallel_operation_abort(env, operation);
        return EXCP_BADARG(env, "Parallel Hash context overflow or cancellation");
    }
    if (status == 0)
        return libdecaf_nif_parallel_operation_await(env, operation);
    return libdecaf_nif_parallel_operation_result(env, operation, state_term);
}

ERL_NIF_TERM
libdecaf_nif_parallel_hash_init_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_hash_parameters_t parameters;
    if (argc != 1 || !libdecaf_nif_hash_parameters(env, argv[0], &parameters) || parameters.algorithm->parallel == NULL)
        return EXCP_BADARG(env, "Expected parallel-capable Hash parameters");
    return parameters.algorithm->parallel_init(env, parameters.argc, parameters.argv);
}

static ERL_NIF_TERM
libdecaf_nif_parallel_hash_begin(ErlNifEnv *env, ERL_NIF_TERM old_term, ERL_NIF_TERM input, bool finish)
{
    const libdecaf_nif_hash_algorithm_t *algorithm;
    libdecaf_nif_hash_state_t *old = libdecaf_nif_hash_get(env, old_term, &algorithm);
    if (old == NULL || algorithm->parallel == NULL)
        return EXCP_BADARG(env, "Expected a parallel Hash state");
    libdecaf_nif_hash_state_t *state = libdecaf_nif_hash_clone(env, old, algorithm);
    if (state == NULL)
        return EXCP_ERROR(env, "Can't allocate parallel Hash context");
    ERL_NIF_TERM state_term = enif_make_resource(env, state), error;
    enif_release_resource(state);
    libdecaf_nif_parallel_operation_t *operation = libdecaf_nif_parallel_operation_create(env,
        libdecaf_nif_parallel_hash_resource_type, state_term, input, finish, 0, &error);
    if (operation == NULL)
        return error;
    ERL_NIF_TERM result = libdecaf_nif_parallel_hash_progress(env, operation);
    enif_release_resource(operation);
    return result;
}

ERL_NIF_TERM
libdecaf_nif_parallel_hash_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2)
        return enif_make_badarg(env);
    return libdecaf_nif_parallel_hash_begin(env, argv[0], argv[1], false);
}

ERL_NIF_TERM
libdecaf_nif_parallel_hash_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2)
        return enif_make_badarg(env);
    ERL_NIF_TERM state = libdecaf_nif_parallel_hash_init_1(env, 1, argv);
    if (enif_is_exception(env, state))
        return state;
    return libdecaf_nif_parallel_hash_begin(env, state, argv[1], true);
}

ERL_NIF_TERM
libdecaf_nif_parallel_hash_continue_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libdecaf_nif_parallel_operation_t *operation;
    if (argc != 1 || (operation = libdecaf_nif_parallel_operation_get(env,
        libdecaf_nif_parallel_hash_resource_type, argv[0])) == NULL)
        return EXCP_BADARG(env, "Expected an owned pending parallel Hash operation");
    return libdecaf_nif_parallel_hash_progress(env, operation);
}

ERL_NIF_TERM
libdecaf_nif_parallel_hash_final_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    const libdecaf_nif_hash_algorithm_t *algorithm;
    if (argc != 1 || libdecaf_nif_hash_get(env, argv[0], &algorithm) == NULL || algorithm->parallel == NULL)
        return EXCP_BADARG(env, "Expected a parallel Hash state");
    return libdecaf_nif_hash_final_1(env, argc, argv);
}
