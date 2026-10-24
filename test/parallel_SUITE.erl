%%% % @format
-module(parallel_SUITE).
-compile(warn_missing_spec_all).
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

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
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

-spec init_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.

-spec end_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
end_per_suite(_) -> ok.

-spec init_per_testcase(TestCase, Config) -> Result when
    TestCase :: ct_suite:ct_testname(), Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_testcase(_, Config) ->
    ok = application:stop(libdecaf),
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.

-spec native_info(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
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
    Info = libdecaf_nif:parallel_router_info(),
    ok.

-spec workers(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
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
    ),
    ok.

-spec wakeup(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
wakeup(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    Router = whereis(Name),
    true = is_pid(Router),
    Absorb = ready_absorb(1),
    ok = await(fun() -> hibernating(Router) end, 7000),
    with_absorb_trace(Absorb, fun() ->
        Name ! wakeup,
        absorb_calls(1),
        Absorb = ready_absorb(1),
        no_absorb_calls()
    end),
    Router = whereis(Name),
    ok = await(fun() -> hibernating(Router) end, 7000),
    ok.

-spec coalescing(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
coalescing(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    First = ready_absorb(1),
    with_absorb_trace(First, fun() ->
        true = erlang:suspend_process(First),
        try
            Name ! wakeup,
            {working, _} = sys:get_state(Name),
            lists:foreach(fun(_) -> Name ! wakeup end, lists:seq(1, 100)),
            {working, _} = sys:get_state(Name)
        after
            true = erlang:resume_process(First)
        end,
        absorb_calls(2),
        _ = ready_absorb(1),
        no_absorb_calls()
    end),
    ok.

-spec startup_wakeup(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
startup_wakeup(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    AbsorbSup = libdecaf_parallel_absorb_sup:child_name(1),
    Old = ready_absorb(1),
    with_absorb_trace(Old, fun() ->
        ok = sys:suspend(AbsorbSup),
        try
            exit(Old, kill),
            ok = await(fun() -> router_state(Name) =:= starting end, 2000),
            lists:foreach(fun(_) -> Name ! wakeup end, lists:seq(1, 100)),
            {starting, _} = sys:get_state(Name, 1000)
        after
            ok = sys:resume(AbsorbSup)
        end,
        absorb_calls(1),
        _ = ready_absorb(1),
        no_absorb_calls()
    end),
    ok.

-spec startup_failures(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
startup_failures(_) ->
    failed_starts(error),
    ok.

-spec starter_crashes(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
starter_crashes(_) ->
    failed_starts(crash),
    ok.

-spec absorb_restart(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
absorb_restart(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    Router = whereis(Name),
    Old = ready_absorb(1),
    Ref = monitor(process, Old),
    exit(Old, kill),
    down(Ref, Old, killed),
    New = ready_absorb(1),
    true = Old =/= New,
    Router = whereis(Name),
    ok.

-spec router_restart(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
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
    AbsorbSup = whereis(libdecaf_parallel_absorb_sup:child_name(1)),
    ok.

-spec restart(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
restart(_) ->
    Name = libdecaf_parallel_router:child_name(1),
    OldRouter = libdecaf_ct:registered_pid(Name),
    AbsorbSupName = libdecaf_parallel_absorb_sup:child_name(1),
    OldSup = whereis(AbsorbSupName),
    true = is_pid(OldSup),
    _ = ready_absorb(1),
    RouterSup = whereis(libdecaf_parallel_router_sup:child_name(1)),
    exit(OldSup, kill),
    ok = await(fun() -> new_process(AbsorbSupName, OldSup) andalso new_process(Name, OldRouter) end, 2000),
    _ = ready_absorb(1),
    RouterSup = whereis(libdecaf_parallel_router_sup:child_name(1)),
    ok.

-spec dirty_cpu(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
dirty_cpu(_) ->
    ok = libdecaf_nif:parallel_absorb(1, 1),
    ok = libdecaf_nif:parallel_absorb(1, 100),
    ok = libdecaf_nif:parallel_absorb(1, 0),
    ok.

-spec disabled(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
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
    workers([]),
    ok.

-spec failed_starts(Mode) -> Result when Mode :: error | crash, Result :: ok.
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
    with_absorb_trace(Old, fun() ->
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
        absorb_calls(1),
        _ = ready_absorb(1),
        no_absorb_calls(),
        Router = whereis(Name),
        AncestorPids = [whereis(Ancestor) || Ancestor <- Ancestors],
        ok
    end).

-spec fail_start_requests(Parent, Mode, Attempt) -> Result when
    Parent :: pid(), Mode :: error | crash, Attempt :: pos_integer(), Result :: no_return().
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

-spec start_attempt(Fake, Attempt) -> Result when Fake :: pid(), Attempt :: pos_integer(), Result :: integer().
start_attempt(Fake, Attempt) ->
    receive
        {start_attempt, Fake, Attempt, Time} -> Time
    after 2000 -> error({no_start_attempt, Attempt})
    end.

-spec ready_absorb(Router) -> Result when Router :: pos_integer(), Result :: pid().
ready_absorb(Number) ->
    Name = libdecaf_parallel_router:child_name(Number),
    ok = await(fun() -> router_state(Name) =:= ready andalso is_pid(only_absorb(Number)) end, 2000),
    Pid = only_absorb(Number),
    true = is_pid(Pid),
    Pid.

-spec only_absorb(Router) -> Result when Router :: pos_integer(), Result :: pid() | undefined.
only_absorb(Number) ->
    Sup = libdecaf_parallel_absorb_sup:child_name(Number),
    case [Pid || {_, Pid, _, _} <- supervisor:which_children(Sup), is_pid(Pid), is_process_alive(Pid)] of
        [Pid] -> Pid;
        _ -> undefined
    end.

-spec new_process(Name, Old) -> Result when Name :: atom(), Old :: pid(), Result :: boolean().
new_process(Name, Old) ->
    Pid = whereis(Name),
    is_pid(Pid) andalso Pid =/= Old.

-spec router_state(Name) -> Result when Name :: atom(), Result :: starting | ready | working.
router_state(Name) ->
    {State, _} = sys:get_state(Name),
    State.

-spec with_absorb_trace(Worker, Function) -> Result when Worker :: pid(), Function :: fun(() -> Value), Result :: Value.
with_absorb_trace(First, Fun) ->
    Session = trace:session_create(?MODULE, self(), []),
    1 = trace:function(Session, {libdecaf_nif, parallel_absorb, 2}, true, []),
    _ = trace:process(Session, new, true, [call]),
    _ = trace:process(Session, First, true, [call]),
    try
        Fun()
    after
        trace:session_destroy(Session)
    end.

-spec absorb_calls(Count) -> Result when Count :: non_neg_integer(), Result :: ok.
absorb_calls(0) ->
    ok;
absorb_calls(Count) ->
    receive
        {trace, _Pid, call, {libdecaf_nif, parallel_absorb, [1, _]}} -> absorb_calls(Count - 1)
    after 3000 -> error({missing_absorb_calls, Count})
    end.

-spec no_absorb_calls() -> Result when Result :: ok.
no_absorb_calls() ->
    receive
        {trace, _Pid, call, {libdecaf_nif, parallel_absorb, [1, _]}} -> error(extra_absorb_call)
    after 100 -> ok
    end.

-spec down(Monitor, Pid, Reason) -> Result when Monitor :: reference(), Pid :: pid(), Reason :: term(), Result :: ok.
down(Ref, Pid, Reason) ->
    receive
        {'DOWN', Ref, process, Pid, Reason} -> ok
    after 4000 -> error({not_down, Pid, Reason})
    end.

-spec hibernating(Pid) -> Result when Pid :: pid(), Result :: boolean().
hibernating(Pid) ->
    case process_info(Pid, current_function) of
        {current_function, {gen_statem, loop_hibernate, 3}} -> true;
        {current_function, {erlang, hibernate, 3}} -> true;
        _ -> false
    end.

-spec await(Predicate, Timeout) -> Result when
    Predicate :: fun(() -> boolean()), Timeout :: non_neg_integer(), Result :: ok.
await(Predicate, Timeout) ->
    await_until(Predicate, erlang:monotonic_time(millisecond) + Timeout).

-spec await_until(Predicate, Deadline) -> Result when
    Predicate :: fun(() -> boolean()), Deadline :: integer(), Result :: ok.
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
