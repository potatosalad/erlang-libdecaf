%%% % @format
-module(phash_worker_SUITE).
-moduledoc """
Parallel-hash worker metadata, supervision, wakeup, and hibernation.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    native_info/1,
    workers/1,
    wakeup/1,
    restart/1,
    disabled/1
]).

all() -> [native_info, workers, wakeup, restart, disabled].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.

end_per_suite(_) -> ok.

native_info(_) ->
    #{count := Count, limit := Limit, names := Names} = Info = libdecaf_nif:phash_worker_info(),
    Count = min(erlang:system_info(schedulers), Limit),
    Count = length(Names),
    Names = [
        binary_to_existing_atom(<<"libdecaf_phash_worker_", (integer_to_binary(N))/binary>>, utf8)
     || N <- lists:seq(1, Count)
    ],
    Online = erlang:system_flag(schedulers_online, 1),
    try
        Info = libdecaf_nif:phash_worker_info()
    after
        erlang:system_flag(schedulers_online, Online)
    end,
    {libdecaf_nif, Beam, Filename} = code:get_object_code(libdecaf_nif),
    {module, libdecaf_nif} = code:load_binary(libdecaf_nif, Filename, Beam),
    Info = libdecaf_nif:phash_worker_info().

workers(_) ->
    #{count := Count, names := Names} = libdecaf_nif:phash_worker_info(),
    Count = length(supervisor:which_children(libdecaf_phash_workers_sup)),
    lists:foreach(
        fun({Number, Name}) ->
            Name = libdecaf_phash_worker:child_name(Number),
            Pid = whereis(Name),
            true = is_pid(Pid),
            {idle, _} = sys:get_state(Pid)
        end,
        lists:enumerate(Names)
    ).

wakeup(_) ->
    #{names := [Name | _]} = libdecaf_nif:phash_worker_info(),
    Pid = whereis(Name),
    true = is_pid(Pid),
    ok = await(fun() -> hibernating(Pid) end, 7000),
    Name ! wakeup,
    {idle, _} = sys:get_state(Pid),
    Pid = whereis(Name),
    ok = await(fun() -> hibernating(Pid) end, 7000).

restart(_) ->
    #{names := [Name | OtherNames]} = libdecaf_nif:phash_worker_info(),
    OtherPids = [whereis(Other) || Other <- OtherNames],
    Pid = whereis(Name),
    true = is_pid(Pid),
    Ref = monitor(process, Pid),
    exit(Pid, kill),
    receive
        {'DOWN', Ref, process, Pid, killed} -> ok
    after 2000 ->
        error(worker_did_not_stop)
    end,
    ok = await(fun() -> is_pid(whereis(Name)) andalso whereis(Name) =/= Pid end, 2000),
    OtherPids = [whereis(Other) || Other <- OtherNames],
    Name ! wakeup,
    {idle, _} = sys:get_state(Name).

disabled(_) ->
    Previous = application:get_env(libdecaf, phash),
    #{names := Names} = Info = libdecaf_nif:phash_worker_info(),
    try
        ok = application:stop(libdecaf),
        ok = application:set_env(libdecaf, phash, false),
        {ok, _} = application:ensure_all_started(libdecaf),
        [] = supervisor:which_children(libdecaf_sup),
        undefined = whereis(libdecaf_phash_workers_sup),
        true = lists:all(fun(Name) -> whereis(Name) =:= undefined end, Names),
        Info = libdecaf_nif:phash_worker_info(),
        <<_:256>> = libdecaf:hash(sha3_256, <<>>)
    after
        ok = application:stop(libdecaf),
        case Previous of
            {ok, Value} -> application:set_env(libdecaf, phash, Value);
            undefined -> application:unset_env(libdecaf, phash)
        end,
        {ok, _} = application:ensure_all_started(libdecaf)
    end,
    workers([]).

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
