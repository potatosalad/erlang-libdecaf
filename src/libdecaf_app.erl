%%% % @format
-module(libdecaf_app).
-moduledoc """
OTP application callback for libdecaf.

Starts `m:libdecaf_sup`, including the parallel router pool by default.
Set the `libdecaf` application environment key `parallel` to `false` before
starting the application to disable the pool. Native cryptographic functions
remain available independently of the router pool.

The `parallel_absorb_rounds` option controls leaves processed per worker call.
It defaults to 100. Zero drains until the pool is idle, so continuous producers
can keep a worker's dirty CPU call running indefinitely.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

-behaviour(application).

%% application callbacks
-export([
    start/2,
    stop/1
]).

%%%=============================================================================
%%% application callbacks
%%%=============================================================================

-doc false.
-spec start(StartType, StartArgs) -> StartResult when
    StartType :: application:start_type(),
    StartArgs :: term(),
    StartResult :: {ok, pid()} | {error, term()}.
start(_StartType, _StartArgs) ->
    case libdecaf_sup:start_link() of
        {ok, Pid} -> {ok, Pid};
        {error, Reason} -> {error, Reason};
        ignore -> {error, supervisor_ignored}
    end.

-doc false.
-spec stop(State) -> Ignored when
    State :: term(),
    Ignored :: ok.
stop(_State) ->
    ok.
