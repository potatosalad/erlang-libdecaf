%%% % @format
-module(parallel_hash_SUITE).
-compile(warn_missing_spec_all).
-moduledoc """
Parallel Hash/XOF framing, ordered joins, retained input, cancellation, and queue budgets.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    boundaries/1,
    streaming/1,
    windows/1,
    concurrent_branches/1,
    concurrent_windows/1,
    pipelined_windows/1,
    round_limits/1,
    yielding/1,
    cancellation/1,
    worker_restart/1,
    retained_binary/1,
    upgrade/1,
    fallback/1,
    invalid_arguments/1
]).

-type hash_progress() ::
    {await, reference(), libdecaf_nif:parallel_hash_operation()}
    | {done, reference(), libdecaf_nif:parallel_hash_state()}
    | {finalize, reference(), libdecaf_nif:parallel_hash_state(), non_neg_integer()}.

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [
        boundaries,
        streaming,
        windows,
        concurrent_branches,
        concurrent_windows,
        pipelined_windows,
        round_limits,
        yielding,
        cancellation,
        worker_restart,
        retained_binary,
        upgrade,
        fallback,
        invalid_arguments
    ].

-spec init_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.

-spec end_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
end_per_suite(_) -> ok.

-spec algorithms() -> Result when
    Result :: [{libdecaf:parallel_hash_parameters(), libdecaf:parallel_xof_parameters(), pos_integer()}].
algorithms() ->
    [
        {kt128, kt128, 8192},
        {kt256, kt256, 8192},
        {{hopmac128, 37, <<"key">>, <<"custom">>}, {hopmac128, <<"key">>, <<"custom">>}, 8192},
        {{hopmac256, 37, <<"key">>, <<"custom">>}, {hopmac256, <<"key">>, <<"custom">>}, 8192},
        {{parallelhash128, 37, 1024, <<"custom">>}, {parallelhashxof128, 1024, <<"custom">>}, 1024},
        {{parallelhash256, 37, 1024, <<"custom">>}, {parallelhashxof256, 1024, <<"custom">>}, 1024}
    ].

-spec boundaries(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
boundaries(_) ->
    lists:foreach(
        fun({Hash, Xof, Block}) ->
            lists:foreach(
                fun(Length) ->
                    Input = data(Length),
                    ExpectedHash = libdecaf:hash(Hash, Input),
                    ExpectedHash = libdecaf:parallel_hash(Hash, Input),
                    ExpectedXof = libdecaf:xof(Xof, Input, 71),
                    ExpectedXof = libdecaf:parallel_xof(Xof, Input, 71),
                    [] = messages()
                end,
                [0, 1, Block - 1, Block, Block + 1, 2 * Block - 1, 2 * Block, 2 * Block + 1, 17 * Block + 37]
            )
        end,
        algorithms()
    ),
    ok.

-spec streaming(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
streaming(_) ->
    lists:foreach(
        fun({Hash, Xof, _}) ->
            Input = data(100003),
            lists:foreach(
                fun(Split) ->
                    <<First:Split/binary, Rest/binary>> = Input,
                    H0 = libdecaf:parallel_hash_init(Hash),
                    H1 = libdecaf:parallel_hash_update(H0, [[], First]),
                    H2 = libdecaf:parallel_hash_update(H1, [Rest, []]),
                    Digest = libdecaf:hash(Hash, Input),
                    Digest = libdecaf:parallel_hash_final(H2),
                    Digest = libdecaf:parallel_hash_final(H2),
                    Empty = libdecaf:hash(Hash, <<>>),
                    Empty = libdecaf:parallel_hash_final(H0),
                    X0 = libdecaf:parallel_xof_init(Xof),
                    X1 = libdecaf:parallel_xof_absorb(X0, First),
                    X2 = libdecaf:parallel_xof_absorb(X1, Rest),
                    {X3, A} = libdecaf:parallel_xof_squeeze(X2, 13),
                    {_, B} = libdecaf:parallel_xof_squeeze(X3, 58),
                    Output = libdecaf:xof(Xof, Input, 71),
                    Output = <<A/binary, B/binary>>,
                    libdecaf_ct:assert_badarg(libdecaf, parallel_xof_absorb, [X3, <<>>])
                end,
                [1, 63, 137, 8191, 8192, 8193]
            )
        end,
        algorithms()
    ),
    ok.

-spec windows(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
windows(_) ->
    Input = data(65 * 1024 * 1024 + 37),
    lists:foreach(
        fun({Hash, Xof, _}) ->
            H = libdecaf:hash(Hash, Input),
            H = libdecaf:parallel_hash(Hash, Input),
            X = libdecaf:xof(Xof, Input, 65537),
            X = libdecaf:parallel_xof(Xof, Input, 65537)
        end,
        algorithms()
    ),
    lists:foreach(
        fun(Block) ->
            Small = data(4 * Block + 17),
            lists:foreach(
                fun({Hash, Xof}) ->
                    H = libdecaf:hash({Hash, 32, Block}, Small),
                    H = libdecaf:parallel_hash({Hash, 32, Block}, Small),
                    X = libdecaf:xof({Xof, Block}, Small, 71),
                    X = libdecaf:parallel_xof({Xof, Block}, Small, 71)
                end,
                [{parallelhash128, parallelhashxof128}, {parallelhash256, parallelhashxof256}]
            )
        end,
        [1, 7, 8, 9, 135, 136, 137, 167, 168, 169, 8192, 8193, 16384]
    ),
    ok.

-spec concurrent_branches(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
concurrent_branches(_) ->
    Hash = libdecaf:parallel_hash_update(libdecaf:parallel_hash_init(kt128), <<"prefix">>),
    Xof = libdecaf:parallel_xof_absorb(libdecaf:parallel_xof_init(kt128), <<"prefix">>),
    Parent = self(),
    Refs = [
        spawn_monitor(fun() ->
            Input = data(300000 + I),
            H = libdecaf:parallel_hash_final(libdecaf:parallel_hash_update(Hash, Input)),
            H = libdecaf:hash(kt128, [<<"prefix">>, Input]),
            {_, X} = libdecaf:parallel_xof_squeeze(libdecaf:parallel_xof_absorb(Xof, Input), 32),
            X = libdecaf:xof(kt128, [<<"prefix">>, Input], 32),
            Parent ! {branch, self()}
        end)
     || I <- lists:seq(1, 16)
    ],
    lists:foreach(
        fun({Pid, Ref}) ->
            receive
                {branch, Pid} -> ok
            after 10000 -> error(branch_timeout)
            end,
            down(Ref, Pid, normal)
        end,
        Refs
    ),
    ok.

-spec concurrent_windows(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
concurrent_windows(_) ->
    % Full windows followed by short ones exercise completion publication while
    % earlier workers are still returning and the collector reuses the slots.
    Input = data(32 * 1024 * 1024 + 17 * 8192 + 37),
    lists:foreach(
        fun({Hash, Xof}) ->
            ExpectedHash = libdecaf:hash(Hash, Input),
            ExpectedXof = libdecaf:xof(Xof, Input, 71),
            Parent = self(),
            Workers = [
                spawn_monitor(fun() ->
                    lists:foreach(
                        fun(_) ->
                            ExpectedHash = libdecaf:parallel_hash(Hash, Input),
                            ExpectedXof = libdecaf:parallel_xof(Xof, Input, 71),
                            [] = messages()
                        end,
                        lists:seq(1, 4)
                    ),
                    Parent ! {windows, self()}
                end)
             || _ <- lists:seq(1, 4)
            ],
            lists:foreach(
                fun({Pid, Ref}) ->
                    receive
                        {windows, Pid} -> ok
                    after 30000 -> error(concurrent_windows_timeout)
                    end,
                    down(Ref, Pid, normal)
                end,
                Workers
            )
        end,
        [{kt128, kt128}, {{parallelhash128, 32, 8192}, {parallelhashxof128, 8192}}]
    ),
    ok.

-spec pipelined_windows(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
pipelined_windows(_) ->
    % Two full windows must be queued before the owner continues. Draining
    % small pieces concurrently exercises split jobs and out-of-order masks.
    Input = data(64 * 1024 * 1024 + 17 * 8192 + 37),
    lists:foreach(
        fun(Parameters) ->
            Expected = libdecaf:hash(Parameters, Input),
            with_paused_routers(fun(Names) ->
                State = libdecaf_nif:parallel_hash_init(Parameters),
                Pending = {await, _, _} = libdecaf_nif:parallel_hash_update(State, Input),
                true = queued() > 4096,
                Drainers = [
                    spawn_monitor(fun() ->
                        lists:foreach(
                            fun(_) -> ok = libdecaf_nif:parallel_absorb(Number, Budget) end,
                            lists:seq(1, 16)
                        )
                    end)
                 || Number <- lists:seq(1, length(Names)), Budget <- [1, 3, 17]
                ],
                lists:foreach(fun({Pid, Ref}) -> down(Ref, Pid, normal) end, Drainers),
                Updated = drain_hash(Pending, length(Names)),
                Expected = libdecaf:parallel_hash_final(Updated),
                0 = queued(),
                [] = messages()
            end)
        end,
        [kt128, {parallelhash256, 64, 8192}]
    ),
    ok.

-spec round_limits(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
round_limits(_) ->
    with_paused_routers(fun(Names) ->
        Input = data(8192 * 257),
        State = libdecaf_nif:parallel_hash_init(kt128),
        Pending = {await, _, _} = libdecaf_nif:parallel_hash_update(State, Input),
        Initial = queued(),
        % The caller may finish a share before yielding; fan-out can use fewer
        % workers than the number of configured schedulers.
        true = Initial > 0 andalso Initial =< 256,
        lists:foreach(
            fun(Number) ->
                Before = queued(),
                ok = libdecaf_nif:parallel_absorb(Number, 1),
                After = queued(),
                true = Before - After >= 0 andalso Before - After =< 1
            end,
            lists:seq(1, length(Names))
        ),
        lists:foreach(
            fun(Number) ->
                Before = queued(),
                ok = libdecaf_nif:parallel_absorb(Number, 3),
                After = queued(),
                true = Before - After >= 0 andalso Before - After =< 3
            end,
            lists:seq(1, length(Names))
        ),
        Progress = lists:foldl(
            fun
                (Number, {await, _, Operation}) ->
                    ok = libdecaf_nif:parallel_absorb(Number, 0),
                    libdecaf_nif:parallel_hash_continue(Operation);
                (_Number, Done) ->
                    Done
            end,
            Pending,
            lists:reverse(lists:seq(1, length(Names)))
        ),
        0 = queued(),
        Updated = native_hash_wait(Progress),
        Expected = libdecaf:hash(kt128, Input),
        Expected = libdecaf:parallel_hash_final(Updated),
        [] = messages()
    end),
    ok.

-spec cancellation(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
cancellation(_) ->
    with_paused_routers(fun(_) ->
        Parent = self(),
        {Pid, Ref} = spawn_monitor(fun() ->
            State = libdecaf_nif:parallel_hash_init(kt128),
            Pending = {await, _, _} = libdecaf_nif:parallel_hash_update(State, data(40 * 1024 * 1024)),
            Parent ! {pending, self()},
            receive
                hold -> Pending
            end
        end),
        receive
            {pending, Pid} -> ok
        after 3000 -> error(no_pending_operation)
        end,
        true = queued() > 0,
        exit(Pid, kill),
        down(Ref, Pid, killed),
        await(fun() -> queued() =:= 0 end)
    end),
    ok.

-spec worker_restart(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
worker_restart(_) ->
    #{names := Names} = libdecaf_nif:parallel_router_info(),
    lists:foreach(fun wait_ready/1, Names),
    Workers = [
        libdecaf_ct:registered_pid(libdecaf_parallel_absorb:child_name(Number))
     || Number <- lists:seq(1, length(Names))
    ],
    lists:foreach(fun(Pid) -> true = erlang:suspend_process(Pid) end, Workers),
    try
        Input = data(3 * 1024 * 1024),
        State = libdecaf_nif:parallel_hash_init(kt128),
        {await, Reference, Operation} = libdecaf_nif:parallel_hash_update(State, Input),
        [First | _] = Workers,
        Monitor = monitor(process, First),
        exit(First, kill),
        down(Monitor, First, killed),
        % The replacement must discover queued work and help the suspended peers.
        receive
            {libdecaf_parallel, Reference} -> ok
        after 5000 -> error(replacement_did_not_drain_queues)
        end,
        Updated = native_hash_wait(libdecaf_nif:parallel_hash_continue(Operation)),
        Expected = libdecaf:hash(kt128, Input),
        Expected = libdecaf:parallel_hash_final(Updated)
    after
        lists:foreach(
            fun(Pid) ->
                case is_process_alive(Pid) of
                    true -> true = erlang:resume_process(Pid);
                    false -> ok
                end
            end,
            Workers
        )
    end,
    ok.

-spec retained_binary(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
retained_binary(_) ->
    Input = data(8 * 1024 * 1024),
    with_paused_routers(fun(_) ->
        Before = binary_memory(),
        State = libdecaf_nif:parallel_hash_init(kt128),
        Pending = {await, _, _} = libdecaf_nif:parallel_hash_update(State, Input),
        After = binary_memory(),
        case {Before, After} of
            {B, A} when is_integer(B), is_integer(A) -> true = A - B < 1024 * 1024;
            _ -> ok
        end,
        % Consume without routers so the retained operation can finish normally.
        #{count := Count} = libdecaf_nif:parallel_router_info(),
        drain_hash(Pending, Count)
    end),
    ok.

-spec upgrade(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
upgrade(_) ->
    with_paused_routers(fun(Names) ->
        Input = data(8192 * 40 + 3),
        S0 = libdecaf_nif:parallel_hash_init(kt128),
        Pending = {await, _, _} = libdecaf_nif:parallel_hash_update(S0, Input),
        Before = queued(),
        {libdecaf_nif, Beam, Filename} = code:get_object_code(libdecaf_nif),
        {module, libdecaf_nif} = code:load_binary(libdecaf_nif, Filename, Beam),
        _ = code:purge(libdecaf_nif),
        Before = queued(),
        lists:foreach(fun(Number) -> libdecaf_nif:parallel_absorb(Number, 0) end, lists:seq(1, length(Names))),
        S1 = native_hash_wait(Pending),
        Expected = libdecaf:hash(kt128, Input),
        Expected = libdecaf:parallel_hash_final(S1)
    end),
    ok.

-spec fallback(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
fallback(_) ->
    ok = application:stop(libdecaf),
    try
        Input = data(100000),
        Expected = libdecaf:hash(kt128, Input),
        Expected = libdecaf:parallel_hash(kt128, Input),
        Expected = libdecaf:parallel_xof(kt128, Input, 32)
    after
        {ok, _} = application:ensure_all_started(libdecaf)
    end,
    ok.

-spec invalid_arguments(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
invalid_arguments(_) ->
    lists:foreach(
        fun(Parameters) ->
            badarg(fun() -> apply(libdecaf, parallel_hash_init, [Parameters]) end),
            badarg(fun() -> apply(libdecaf, parallel_xof_init, [Parameters]) end)
        end,
        [sha2_512, sha3_256, shake128, {cshake128, 32}, {kmac128, 32, <<>>}, {parallelhash128, 32, 0}]
    ),
    H = libdecaf:parallel_hash_init(kt128),
    X = libdecaf:parallel_xof_init(kt128),
    badarg(fun() -> apply(libdecaf, parallel_hash_update, [X, <<>>]) end),
    badarg(fun() -> apply(libdecaf, parallel_xof_absorb, [H, <<>>]) end),
    badarg(fun() -> apply(libdecaf, parallel_hash_update, [H, [256]]) end),
    badarg(fun() -> apply(libdecaf_nif, parallel_absorb, [1, -1]) end),
    badarg(fun() -> apply(libdecaf_nif, parallel_absorb, [0, 0]) end),
    ok.

-spec with_paused_routers(Function) -> Result when Function :: fun(([atom()]) -> Value), Result :: Value.
with_paused_routers(Fun) ->
    #{names := Names} = libdecaf_nif:parallel_router_info(),
    lists:foreach(
        fun(Name) ->
            {ready, _} = wait_ready(Name),
            ok = sys:suspend(Name)
        end,
        Names
    ),
    Workers = [
        libdecaf_ct:registered_pid(libdecaf_parallel_absorb:child_name(Number))
     || Number <- lists:seq(1, length(Names))
    ],
    lists:foreach(fun(Pid) -> true = erlang:suspend_process(Pid) end, Workers),
    try
        Fun(Names)
    after
        lists:foreach(fun(Pid) -> true = erlang:resume_process(Pid) end, Workers),
        lists:foreach(fun(Name) -> ok = sys:resume(Name) end, Names)
    end.

-spec wait_ready(Name) -> Result when Name :: atom(), Result :: {ready, tuple()}.
wait_ready(Name) ->
    await(fun() ->
        {State, _} = sys:get_state(Name),
        State =:= ready
    end),
    sys:get_state(Name).

-spec native_hash_wait(Progress) -> Result when
    Progress :: hash_progress(), Result :: libdecaf_nif:parallel_hash_state().
native_hash_wait({finalize, _, _, _}) ->
    error(unexpected_parallel_finalize);
native_hash_wait({await, Ref, Operation}) ->
    receive
        {libdecaf_parallel, Ref} -> ok
    after 50 -> ok
    end,
    native_hash_wait(libdecaf_nif:parallel_hash_continue(Operation));
native_hash_wait({done, Ref, State}) ->
    flush(Ref),
    State.

-spec drain_hash(Progress, RouterCount) -> Result when
    Progress :: hash_progress(), RouterCount :: pos_integer(), Result :: libdecaf_nif:parallel_hash_state().
drain_hash({finalize, _, _, _}, _) ->
    error(unexpected_parallel_finalize);
drain_hash({await, _, Operation}, Count) ->
    lists:foreach(fun(Number) -> libdecaf_nif:parallel_absorb(Number, 0) end, lists:seq(1, Count)),
    drain_hash(libdecaf_nif:parallel_hash_continue(Operation), Count);
drain_hash({done, Ref, State}, _) ->
    flush(Ref),
    State.

-spec binary_memory() -> Result when Result :: non_neg_integer() | unavailable.
binary_memory() ->
    % ASan emulators can disable allocator statistics; still exercise retention
    % and release under ASan, with the allocation bound checked on ordinary OTP.
    try
        erlang:memory(binary)
    catch
        error:notsup -> unavailable
    end.

-spec queued() -> Result when Result :: non_neg_integer().
queued() ->
    #{queued := Count} = libdecaf_nif:parallel_router_info(),
    Count.

-spec data(Length) -> Result when Length :: non_neg_integer(), Result :: binary().
data(Length) ->
    Block = list_to_binary(lists:seq(0, 250)),
    binary:part(binary:copy(Block, (Length + 250) div 251), 0, Length).

-spec messages() -> Result when Result :: [reference()].
messages() ->
    receive
        {libdecaf_parallel, Ref} -> [Ref | messages()]
    after 0 -> []
    end.

-spec flush(Reference) -> Result when Reference :: reference(), Result :: ok.
flush(Ref) ->
    receive
        {libdecaf_parallel, Ref} -> flush(Ref)
    after 0 -> ok
    end.

-spec down(Monitor, Pid, Reason) -> Result when Monitor :: reference(), Pid :: pid(), Reason :: term(), Result :: ok.
down(Ref, Pid, Reason) ->
    receive
        {'DOWN', Ref, process, Pid, Reason} -> ok
    after 5000 -> error({not_down, Pid, Reason})
    end.

-spec await(Predicate) -> Result when Predicate :: fun(() -> boolean()), Result :: ok.
await(Predicate) -> await_until(Predicate, erlang:monotonic_time(millisecond) + 5000).
-spec await_until(Predicate, Deadline) -> Result when
    Predicate :: fun(() -> boolean()), Deadline :: integer(), Result :: ok.
await_until(Predicate, Deadline) ->
    case Predicate() of
        true ->
            ok;
        false ->
            true = erlang:monotonic_time(millisecond) < Deadline,
            receive
            after 10 -> ok
            end,
            await_until(Predicate, Deadline)
    end.

-spec badarg(Function) -> Result when Function :: fun(() -> term()), Result :: ok.
badarg(Fun) ->
    try Fun() of
        Value -> error({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _} -> ok;
        error:{badarg, _, _} -> ok
    end.

-spec yielding(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
yielding(_) ->
    lists:foreach(
        fun(Budget) ->
            with_paused_routers(fun(_) ->
                Input = data(8192 * 1025),
                State = libdecaf_nif:parallel_hash_init(kt128),
                Pending = {await, _, _} = libdecaf_nif:parallel_hash_update(State, Input),
                Parent = self(),
                {Pid, Monitor} = spawn_opt(
                    fun() ->
                        receive
                            go ->
                                ok = libdecaf_nif:parallel_absorb(1, Budget),
                                Parent ! {drained, self()}
                        end
                    end,
                    [monitor, {priority, low}]
                ),
                erlang:trace(Pid, true, [running]),
                Pid ! go,
                try
                    await_drain_yield(Pid, Monitor, false),
                    0 = queued(),
                    {await, _, Operation} = Pending,
                    {done, _, Updated} = libdecaf_nif:parallel_hash_continue(Operation),
                    Expected = libdecaf:hash(kt128, Input),
                    Expected = libdecaf:parallel_hash_final(Updated)
                after
                    exit(Pid, kill),
                    erlang:demonitor(Monitor, [flush]),
                    flush_drain_trace(Pid)
                end
            end)
        end,
        [0, 16#FFFFFFFF]
    ),
    ok.

-spec await_drain_yield(Pid, Monitor, Yielded) -> Result when
    Pid :: pid(), Monitor :: reference(), Yielded :: boolean(), Result :: ok.
await_drain_yield(Pid, Monitor, Yielded) ->
    receive
        {trace, Pid, out, {libdecaf_nif, libdecaf_nif_parallel_absorb_continue, 2}} ->
            await_drain_yield(Pid, Monitor, true);
        {trace, Pid, _, _} ->
            await_drain_yield(Pid, Monitor, Yielded);
        {drained, Pid} when Yielded -> ok;
        {drained, Pid} ->
            ct:fail(parallel_absorb_did_not_yield);
        {'DOWN', Monitor, process, Pid, Reason} ->
            ct:fail({parallel_absorb_failed, Reason})
    after 10000 -> ct:fail(parallel_absorb_yield_timeout)
    end.

-spec flush_drain_trace(Pid) -> Result when Pid :: pid(), Result :: ok.
flush_drain_trace(Pid) ->
    receive
        {trace, Pid, _, _} -> flush_drain_trace(Pid)
    after 0 -> ok
    end.
