%%% % @format
-module(spongerng_random_SUITE).
-compile(warn_missing_spec_all).
-moduledoc """
Automatically seeded thread-local SpongeRNG output, concurrency, and lifecycle.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    lengths/1,
    invalid_arguments/1,
    concurrent/1,
    fallback_seed/1,
    cancellation/1,
    trapping/1,
    upgrade/1
]).

-spec all() -> Tests when Tests :: [ct_suite:ct_test_def()].
all() -> [lengths, invalid_arguments, concurrent, fallback_seed, cancellation, trapping, upgrade].

-spec lengths(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
lengths(_) ->
    lists:foreach(
        fun(Length) ->
            Length = byte_size(libdecaf:strong_rand_bytes(Length))
        end,
        [0, 1, 31, 32, 64, 255, 256, 257, 4095, 4096, 4097, 65535, 65536, 65537, 17 * 1024 * 1024, 32]
    ),
    <<>> = libdecaf_nif:strong_rand_bytes(0),
    ok.

-spec invalid_arguments(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
invalid_arguments(_) ->
    lists:foreach(
        fun(Length) ->
            lists:foreach(
                fun(Module) -> libdecaf_ct:assert_badarg(Module, strong_rand_bytes, [Length]) end,
                [libdecaf, libdecaf_nif]
            )
        end,
        [-1, 1.0, <<32>>, [32], undefined, 1 bsl 128]
    ),
    lists:foreach(
        fun(Seed) -> libdecaf_ct:assert_badarg(libdecaf_nif, strong_rand_bytes, [32, Seed]) end,
        [<<>>, <<0:504>>, <<0:520>>, [binary:copy(<<1>>, 64)], undefined]
    ),
    libdecaf_ct:assert_badarg(libdecaf_nif, strong_rand_bytes, [-1, crypto:strong_rand_bytes(64)]),
    ok.

-spec concurrent(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
concurrent(_) ->
    Parent = self(),
    Workers = [
        spawn_monitor(fun() ->
            Outputs = [libdecaf:strong_rand_bytes(32) || _ <- lists:seq(1, 64)],
            Parent ! {self(), Outputs}
        end)
     || _ <- lists:seq(1, 64)
    ],
    Outputs = lists:append([worker_output(Worker) || Worker <- Workers]),
    4096 = length(Outputs),
    4096 = length(lists:usort(Outputs)),
    ok.

-spec fallback_seed(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
fallback_seed(_) ->
    Seed = crypto:strong_rand_bytes(64),
    <<>> = libdecaf_nif:strong_rand_bytes(0, Seed),
    A = libdecaf_nif:strong_rand_bytes(32, Seed),
    B = libdecaf_nif:strong_rand_bytes(32, Seed),
    32 = byte_size(A),
    32 = byte_size(B),
    true = A =/= B,
    32 = byte_size(libdecaf:strong_rand_bytes(32)),
    ok.

-spec cancellation(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
cancellation(_) ->
    traced_random(64 * 1024 * 1024, true),
    32 = byte_size(libdecaf:strong_rand_bytes(32)),
    ok.

-spec trapping(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
trapping(_) ->
    traced_random(1024 * 1024, false).

-spec traced_random(Length, Cancel) -> Result when Length :: pos_integer(), Cancel :: boolean(), Result :: ok.
traced_random(Length, Cancel) ->
    Parent = self(),
    {Pid, Monitor} = spawn_opt(
        fun() ->
            receive
                go ->
                    Output = libdecaf:strong_rand_bytes(Length),
                    Parent ! {random_output, self(), byte_size(Output)}
            end
        end,
        [monitor, {priority, low}]
    ),
    erlang:trace(Pid, true, [running]),
    Pid ! go,
    try
        await_random_yield(Pid, Monitor, Length, Cancel, false)
    after
        exit(Pid, kill),
        erlang:demonitor(Monitor, [flush]),
        flush_random_trace(Pid)
    end.

-spec await_random_yield(Pid, Monitor, Length, Cancel, Yielded) -> Result when
    Pid :: pid(),
    Monitor :: reference(),
    Length :: pos_integer(),
    Cancel :: boolean(),
    Yielded :: boolean(),
    Result :: ok.
await_random_yield(Pid, Monitor, Length, Cancel, Yielded) ->
    receive
        {trace, Pid, out, {libdecaf_nif, libdecaf_nif_random_continue, 1}} when Cancel ->
            exit(Pid, kill),
            receive
                {'DOWN', Monitor, process, Pid, killed} -> ok
            after 5000 -> ct:fail(random_generation_did_not_cancel)
            end;
        {trace, Pid, out, {libdecaf_nif, libdecaf_nif_random_continue, 1}} ->
            await_random_yield(Pid, Monitor, Length, Cancel, true);
        {trace, Pid, _, _} ->
            await_random_yield(Pid, Monitor, Length, Cancel, Yielded);
        {random_output, Pid, Length} when Yielded -> ok;
        {random_output, Pid, _} ->
            ct:fail(random_generation_did_not_yield);
        {'DOWN', Monitor, process, Pid, Reason} ->
            ct:fail({random_generation_failed, Reason})
    after 5000 -> ct:fail(random_generation_timed_out)
    end.

-spec flush_random_trace(Pid) -> Result when Pid :: pid(), Result :: ok.
flush_random_trace(Pid) ->
    receive
        {trace, Pid, _, _} -> flush_random_trace(Pid)
    after 0 -> ok
    end.

-spec upgrade(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
upgrade(_) ->
    {libdecaf_nif, Beam, Filename} = code:get_object_code(libdecaf_nif),
    lists:foreach(
        fun(_) ->
            Before = libdecaf:strong_rand_bytes(32),
            {module, libdecaf_nif} = code:load_binary(libdecaf_nif, Filename, Beam),
            true = code:soft_purge(libdecaf_nif),
            After = libdecaf:strong_rand_bytes(32),
            true = Before =/= After,
            32 = byte_size(After)
        end,
        lists:seq(1, 3)
    ),
    ok.

-spec worker_output(Worker) -> Output when Worker :: {pid(), reference()}, Output :: [binary()].
worker_output({Pid, Monitor}) ->
    receive
        {Pid, Outputs} ->
            receive
                {'DOWN', Monitor, process, Pid, normal} -> Outputs;
                {'DOWN', Monitor, process, Pid, Reason} -> ct:fail({worker_failed, Reason})
            after 5000 -> ct:fail(worker_did_not_exit)
            end;
        {'DOWN', Monitor, process, Pid, Reason} ->
            ct:fail({worker_failed, Reason})
    after 10000 -> ct:fail(random_generation_timed_out)
    end.
