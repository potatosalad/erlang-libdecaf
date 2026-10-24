%%% % @format
-module(parallel_SUITE).
-moduledoc """
Parallel router supervision, asynchronous absorb startup, and wakeup coalescing.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    native_info/1,
    workers/1,
    wakeup/1,
    restart/1,
    router_restart/1,
    absorb_restart/1,
    coalescing/1,
    startup_wakeup/1,
    startup_failures/1,
    starter_crashes/1,
    dirty_cpu/1,
    disabled/1
]).

all() ->
    [
        native_info,
        workers,
        wakeup,
        coalescing,
        startup_wakeup,
        startup_failures,
        starter_crashes,
        absorb_restart,
        router_restart,
        restart,
        dirty_cpu,
        disabled
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.

end_per_suite(_) -> ok.

init_per_testcase(_, Config) ->
    ok = application:stop(libdecaf),
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.

native_info(_) ->
    #{count := Count, limit := Limit, names := Names} = Info = libdecaf_nif:parallel_router_info(),
    Count = min(erlang:system_info(schedulers), Limit),
    Count = length(Names),
    Names = [
        binary_to_existing_atom(<<"libdecaf_parallel_router_", (integer_to_binary(N))/binary>>, utf8)
     || N <- lists:seq(1, Count)
    ],
    Online = erlang:system_flag(schedulers_online, 1),
    try
        Info = libdecaf_nif:parallel_router_info()
    after
        erlang:system_flag(schedulers_online, Online)
    end,
    {libdecaf_nif, Beam, Filename} = code:get_object_code(libdecaf_nif),
    {module, libdecaf_nif} = code:load_binary(libdecaf_nif, Filename, Beam),
    Info = libdecaf_nif:parallel_router_info().

workers(_) ->
    #{count := Count, names := Names} = libdecaf_nif:parallel_router_info(),
    Count = length(supervisor:which_children(libdecaf_parallel_routers_sup)),
    lists:foreach(
        fun({Number, Name}) ->
            Name = libdecaf_parallel_router:child_name(Number),
            Pid = whereis(Name),
            true = is_pid(Pid),
            ready_absorb(Number)
        end,
        lists:enumerate(Names)
    ).

wakeup(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    Router = whereis(Name),
    true = is_pid(Router),
    Absorb = ready_absorb(1),
    ok = await(fun() -> hibernating(Router) end, 7000),
    Ref = monitor(process, Absorb),
    Name ! wakeup,
    down(Ref, Absorb, normal),
    _ = ready_absorb(1),
    Router = whereis(Name),
    ok = await(fun() -> hibernating(Router) end, 7000).

coalescing(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    First = ready_absorb(1),
    FirstRef = monitor(process, First),
    Name ! wakeup,
    ok = await(fun() -> in_nif(First) end, 2000),
    lists:foreach(fun(_) -> Name ! wakeup end, lists:seq(1, 100)),
    {working, _} = sys:get_state(Name),
    down(FirstRef, First, normal),
    ok = await(fun() -> different_absorb(1, First) end, 2000),
    Second = only_absorb(1),
    true = is_pid(Second),
    SecondRef = monitor(process, Second),
    ok = await(fun() -> in_nif(Second) end, 2000),
    down(SecondRef, Second, normal),
    Third = ready_absorb(1),
    % No third run should be triggered by the other 99 wakeups.
    receive
    after 1100 -> ok
    end,
    Third = ready_absorb(1).

startup_wakeup(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    AbsorbSup = libdecaf_parallel_absorb_sup:child_name(1),
    Old = ready_absorb(1),
    ok = sys:suspend(AbsorbSup),
    try
        exit(Old, kill),
        ok = await(fun() -> router_state(Name) =:= starting end, 2000),
        lists:foreach(fun(_) -> Name ! wakeup end, lists:seq(1, 100)),
        % A suspended child supervisor must not block the router.
        {starting, _} = sys:get_state(Name, 1000)
    after
        ok = sys:resume(AbsorbSup)
    end,
    ok = await(fun() -> different_absorb(1, Old) end, 2000),
    Running = only_absorb(1),
    true = is_pid(Running),
    Ref = monitor(process, Running),
    ok = await(fun() -> in_nif(Running) end, 2000),
    down(Ref, Running, normal),
    Prepared = ready_absorb(1),
    receive
    after 1100 -> ok
    end,
    Prepared = ready_absorb(1).

startup_failures(_) ->
    failed_starts(error).

starter_crashes(_) ->
    failed_starts(crash).

absorb_restart(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    Router = whereis(Name),
    Old = ready_absorb(1),
    Ref = monitor(process, Old),
    exit(Old, kill),
    down(Ref, Old, killed),
    New = ready_absorb(1),
    true = Old =/= New,
    Router = whereis(Name).

router_restart(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    Old = whereis(Name),
    true = is_pid(Old),
    Absorb = ready_absorb(1),
    AbsorbSup = whereis(libdecaf_parallel_absorb_sup:child_name(1)),
    Ref = monitor(process, Absorb),
    exit(Old, kill),
    down(Ref, Absorb, normal),
    ok = await(fun() -> new_process(Name, Old) end, 2000),
    _ = ready_absorb(1),
    AbsorbSup = whereis(libdecaf_parallel_absorb_sup:child_name(1)).

restart(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    OldRouter = whereis(Name),
    AbsorbSupName = libdecaf_parallel_absorb_sup:child_name(1),
    OldSup = whereis(AbsorbSupName),
    true = is_pid(OldSup),
    _ = ready_absorb(1),
    RouterSup = whereis(libdecaf_parallel_router_sup:child_name(1)),
    exit(OldSup, kill),
    ok = await(fun() -> new_process(AbsorbSupName, OldSup) andalso new_process(Name, OldRouter) end, 2000),
    _ = ready_absorb(1),
    RouterSup = whereis(libdecaf_parallel_router_sup:child_name(1)).

dirty_cpu(_) ->
    Online = erlang:system_flag(schedulers_online, 1),
    try
        Parent = self(),
        {Pid, Ref} = spawn_monitor(fun() ->
            Parent ! {entering, self()},
            Start = erlang:monotonic_time(millisecond),
            ok = libdecaf_nif:parallel_absorb(),
            Parent ! {finished, self(), erlang:monotonic_time(millisecond) - Start}
        end),
        receive
            {entering, Pid} -> ok
        after 2000 -> error(not_started)
        end,
        receive
        after 100 -> ok
        end,
        % With one normal scheduler, it must remain responsive during the NIF.
        true = is_process_alive(Pid),
        receive
            {finished, Pid, Duration} when Duration >= 1000 -> ok
        after 3000 -> error(not_finished)
        end,
        down(Ref, Pid, normal)
    after
        erlang:system_flag(schedulers_online, Online)
    end.

disabled(_) ->
    Previous = application:get_env(libdecaf, parallel),
    #{names := Names} = Info = libdecaf_nif:parallel_router_info(),
    try
        ok = application:stop(libdecaf),
        ok = application:set_env(libdecaf, parallel, false),
        {ok, _} = application:ensure_all_started(libdecaf),
        [] = supervisor:which_children(libdecaf_sup),
        undefined = whereis(libdecaf_parallel_routers_sup),
        true = lists:all(fun(Name) -> whereis(Name) =:= undefined end, Names),
        Info = libdecaf_nif:parallel_router_info(),
        <<_:256>> = libdecaf:hash(sha3_256, <<>>)
    after
        ok = application:stop(libdecaf),
        case Previous of
            {ok, Value} -> application:set_env(libdecaf, parallel, Value);
            undefined -> application:unset_env(libdecaf, parallel)
        end,
        {ok, _} = application:ensure_all_started(libdecaf)
    end,
    workers([]).

failed_starts(Mode) ->
    Name = libdecaf_parallel_router:child_name(1),
    Router = whereis(Name),
    SupName = libdecaf_parallel_absorb_sup:child_name(1),
    Sup = whereis(SupName),
    true = is_pid(Sup),
    Ancestors = [libdecaf_sup, libdecaf_parallel_routers_sup, libdecaf_parallel_router_sup:child_name(1)],
    AncestorPids = [whereis(Ancestor) || Ancestor <- Ancestors],
    Old = ready_absorb(1),
    Parent = self(),
    Fake = spawn(fun() -> fail_start_requests(Parent, Mode, 1) end),
    true = unregister(SupName),
    true = register(SupName, Fake),
    try
        exit(Old, kill),
        FirstAttempt = start_attempt(Fake, 1),
        lists:foreach(fun(_) -> Name ! wakeup end, lists:seq(1, 100)),
        _ = start_attempt(Fake, 2),
        _ = start_attempt(Fake, 3),
        LastAttempt = start_attempt(Fake, 4),
        true = LastAttempt - FirstAttempt >= 700,
        Router = whereis(Name),
        AncestorPids = [whereis(Ancestor) || Ancestor <- Ancestors],
        {starting, _} = sys:get_state(Name, 1000)
    after
        true = unregister(SupName),
        true = register(SupName, Sup),
        exit(Fake, kill)
    end,
    ok = await(fun() -> different_absorb(1, Old) end, 2000),
    Running = only_absorb(1),
    true = is_pid(Running),
    Ref = monitor(process, Running),
    ok = await(fun() -> in_nif(Running) end, 2000),
    down(Ref, Running, normal),
    Prepared = ready_absorb(1),
    receive
    after 1100 -> ok
    end,
    Prepared = ready_absorb(1),
    Router = whereis(Name),
    AncestorPids = [whereis(Ancestor) || Ancestor <- Ancestors].

fail_start_requests(Parent, Mode, Attempt) ->
    receive
        {'$gen_call', From = {Starter, _Tag}, {start_child, _Args}} ->
            Parent ! {start_attempt, self(), Attempt, erlang:monotonic_time(millisecond)},
            case Mode of
                error -> gen_server:reply(From, {error, temporarily_unavailable});
                crash -> exit(Starter, kill)
            end,
            fail_start_requests(Parent, Mode, Attempt + 1)
    end.

start_attempt(Fake, Attempt) ->
    receive
        {start_attempt, Fake, Attempt, Time} -> Time
    after 2000 -> error({no_start_attempt, Attempt})
    end.

ready_absorb(Number) ->
    Name = libdecaf_parallel_router:child_name(Number),
    ok = await(fun() -> router_state(Name) =:= ready andalso is_pid(only_absorb(Number)) end, 2000),
    only_absorb(Number).

only_absorb(Number) ->
    Sup = libdecaf_parallel_absorb_sup:child_name(Number),
    case [Pid || {_, Pid, _, _} <- supervisor:which_children(Sup), is_pid(Pid), is_process_alive(Pid)] of
        [Pid] -> Pid;
        _ -> undefined
    end.

different_absorb(Number, Old) ->
    Pid = only_absorb(Number),
    is_pid(Pid) andalso Pid =/= Old.

new_process(Name, Old) ->
    Pid = whereis(Name),
    is_pid(Pid) andalso Pid =/= Old.

router_state(Name) ->
    {State, _} = sys:get_state(Name),
    State.

in_nif(Pid) ->
    process_info(Pid, current_function) =:= {current_function, {libdecaf_nif, parallel_absorb, 0}}.

down(Ref, Pid, Reason) ->
    receive
        {'DOWN', Ref, process, Pid, Reason} -> ok
    after 4000 -> error({not_down, Pid, Reason})
    end.

hibernating(Pid) ->
    case process_info(Pid, current_function) of
        {current_function, {gen_statem, loop_hibernate, 3}} -> true;
        {current_function, {erlang, hibernate, 3}} -> true;
        _ -> false
    end.

await(Predicate, Timeout) ->
    await_until(Predicate, erlang:monotonic_time(millisecond) + Timeout).

await_until(Predicate, Deadline) ->
    case Predicate() of
        true ->
            ok;
        false ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    receive
                    after 25 -> ok
                    end,
                    await_until(Predicate, Deadline);
                false ->
                    error(timeout)
            end
    end.
