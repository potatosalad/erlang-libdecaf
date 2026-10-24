%%% % @format
-module(parallel_hash_SUITE).
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
    round_limits/1,
    cancellation/1,
    retained_binary/1,
    upgrade/1,
    fallback/1,
    invalid_arguments/1
]).

all() ->
    [
        boundaries,
        streaming,
        windows,
        concurrent_branches,
        round_limits,
        cancellation,
        retained_binary,
        upgrade,
        fallback,
        invalid_arguments
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.

end_per_suite(_) -> ok.

algorithms() ->
    [
        {kt128, kt128, 8192},
        {kt256, kt256, 8192},
        {{hopmac128, 37, <<"key">>, <<"custom">>}, {hopmac128, <<"key">>, <<"custom">>}, 8192},
        {{hopmac256, 37, <<"key">>, <<"custom">>}, {hopmac256, <<"key">>, <<"custom">>}, 8192},
        {{parallelhash128, 37, 1024, <<"custom">>}, {parallelhashxof128, 1024, <<"custom">>}, 1024},
        {{parallelhash256, 37, 1024, <<"custom">>}, {parallelhashxof256, 1024, <<"custom">>}, 1024}
    ].

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
    ).

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
                    badarg(fun() -> libdecaf:parallel_xof_absorb(X3, <<>>) end)
                end,
                [1, 63, 137, 8191, 8192, 8193]
            )
        end,
        algorithms()
    ).

windows(_) ->
    Input = data(5 * 1024 * 1024 + 37),
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
    ).

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
    ).

round_limits(_) ->
    with_paused_routers(fun(Names) ->
        Input = data(8192 * 257),
        State = libdecaf_nif:parallel_hash_init(kt128),
        Pending = {await, _, _} = libdecaf_nif:parallel_hash_update(State, Input),
        256 = queued(),
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
    end).

cancellation(_) ->
    with_paused_routers(fun(_) ->
        Parent = self(),
        {Pid, Ref} = spawn_monitor(fun() ->
            State = libdecaf_nif:parallel_hash_init(kt128),
            Pending = {await, _, _} = libdecaf_nif:parallel_hash_update(State, data(3000000)),
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
    end).

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
    end).

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
    end).

fallback(_) ->
    ok = application:stop(libdecaf),
    try
        Input = data(100000),
        Expected = libdecaf:hash(kt128, Input),
        Expected = libdecaf:parallel_hash(kt128, Input),
        Expected = libdecaf:parallel_xof(kt128, Input, 32)
    after
        {ok, _} = application:ensure_all_started(libdecaf)
    end.

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
    badarg(fun() -> apply(libdecaf_nif, parallel_absorb, [0, 0]) end).

with_paused_routers(Fun) ->
    #{names := Names} = libdecaf_nif:parallel_router_info(),
    lists:foreach(
        fun(Name) ->
            {ready, _} = wait_ready(Name),
            ok = sys:suspend(Name)
        end,
        Names
    ),
    try
        Fun(Names)
    after
        lists:foreach(fun(Name) -> ok = sys:resume(Name) end, Names)
    end.

wait_ready(Name) ->
    await(fun() ->
        {State, _} = sys:get_state(Name),
        State =:= ready
    end),
    sys:get_state(Name).

native_hash_wait({await, Ref, Operation}) ->
    receive
        {libdecaf_parallel, Ref} -> ok
    after 50 -> ok
    end,
    native_hash_wait(libdecaf_nif:parallel_hash_continue(Operation));
native_hash_wait({done, Ref, State}) ->
    flush(Ref),
    State.

drain_hash({await, _, Operation}, Count) ->
    lists:foreach(fun(Number) -> libdecaf_nif:parallel_absorb(Number, 0) end, lists:seq(1, Count)),
    drain_hash(libdecaf_nif:parallel_hash_continue(Operation), Count);
drain_hash({done, Ref, _State}, _) ->
    flush(Ref).

binary_memory() ->
    % ASan emulators can disable allocator statistics; still exercise retention
    % and release under ASan, with the allocation bound checked on ordinary OTP.
    try
        erlang:memory(binary)
    catch
        error:notsup -> unavailable
    end.

queued() ->
    #{queued := Count} = libdecaf_nif:parallel_router_info(),
    Count.

data(Length) ->
    Block = list_to_binary(lists:seq(0, 250)),
    binary:part(binary:copy(Block, (Length + 250) div 251), 0, Length).

messages() ->
    receive
        {libdecaf_parallel, Ref} -> [Ref | messages()]
    after 0 -> []
    end.

flush(Ref) ->
    receive
        {libdecaf_parallel, Ref} -> flush(Ref)
    after 0 -> ok
    end.

down(Ref, Pid, Reason) ->
    receive
        {'DOWN', Ref, process, Pid, Reason} -> ok
    after 5000 -> error({not_down, Pid, Reason})
    end.

await(Predicate) -> await_until(Predicate, erlang:monotonic_time(millisecond) + 5000).
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

badarg(Fun) ->
    try Fun() of
        Value -> error({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _} -> ok;
        error:{badarg, _, _} -> ok
    end.
