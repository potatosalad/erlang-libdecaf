%%% % @format
-module(libdecaf_app).
-moduledoc """
OTP application callback for libdecaf.

Starts `m:libdecaf_sup`, including the parallel-hash worker pool by default.
Set the `libdecaf` application environment key `phash` to `false` before
starting the application to disable the pool. Native cryptographic functions
remain available independently of the worker pool.
""".
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
