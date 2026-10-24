%%% % @format
-module(libdecaf_phash_worker).
-moduledoc """
Numbered parallel-hash worker scaffolding.

Workers are registered as `libdecaf_phash_worker_1`, `libdecaf_phash_worker_2`,
and so on, using the names allocated by the NIF. They hibernate after five
seconds of inactivity. Sending the atom `wakeup` wakes a worker; the handler
is the future entry point for native parallel-hash work.

```erlang
{ok, _} = application:ensure_all_started(libdecaf),
#{names := [WorkerName | _]} = libdecaf_nif:phash_worker_info(),
WorkerName ! wakeup.
```
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

-behaviour(gen_statem).

%% OTP callbacks
-export([
    child_name/1,
    child_spec/1,
    start_link/2
]).
%% gen_statem callbacks
-export([
    callback_mode/0,
    init/1
]).
%% gen_statem states
-export([
    idle/3
]).

-record(data, {
    worker_number :: worker_number()
}).

-type data() :: #data{}.
-doc "One-based worker index into the NIF's registered-name list.".
-type worker_number() :: pos_integer().

-export_type([
    worker_number/0
]).

%%%=============================================================================
%%% OTP callbacks
%%%=============================================================================

-doc "Return an existing worker name allocated by the NIF.".
-spec child_name(WorkerNumber) -> ChildName when
    WorkerNumber :: worker_number(), ChildName :: atom().
child_name(WorkerNumber) when is_integer(WorkerNumber), WorkerNumber >= 1 ->
    #{names := Names} = libdecaf_nif:phash_worker_info(),
    lists:nth(WorkerNumber, Names).

-doc "Return the child specification for a numbered worker.".
-spec child_spec(WorkerNumber) -> ChildSpec when
    WorkerNumber :: worker_number(), ChildSpec :: supervisor:child_spec().
child_spec(WorkerNumber) when is_integer(WorkerNumber), WorkerNumber >= 1 ->
    ChildName = child_name(WorkerNumber),
    #{
        id => ChildName,
        start => {?MODULE, start_link, [{local, ChildName}, WorkerNumber]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [?MODULE]
    }.

-doc "Start a worker with a five-second idle hibernation timeout.".
-spec start_link(ServerName, WorkerNumber) -> StartResult when
    ServerName :: gen_statem:server_name(),
    WorkerNumber :: worker_number(),
    StartResult :: gen_statem:start_ret().
start_link(ServerName, WorkerNumber) when is_integer(WorkerNumber), WorkerNumber >= 1 ->
    _ = child_name(WorkerNumber),
    gen_statem:start_link(ServerName, ?MODULE, WorkerNumber, [{hibernate_after, 5000}]).

%%%=============================================================================
%%% gen_statem callbacks
%%%=============================================================================

-doc false.
-spec callback_mode() -> CallbackMode when CallbackMode :: gen_statem:callback_mode_result().
callback_mode() ->
    [state_functions].

-doc false.
-spec init(WorkerNumber) -> InitResult when
    WorkerNumber :: worker_number(), InitResult :: {ok, idle, data()}.
init(WorkerNumber) ->
    {ok, idle, #data{worker_number = WorkerNumber}}.

%%%=============================================================================
%%% gen_statem states
%%%=============================================================================

-doc false.
-spec idle(EventType, EventContent, Data) -> HandleEventResult when
    EventType :: gen_statem:event_type(),
    EventContent :: term(),
    Data :: data(),
    HandleEventResult :: gen_statem:event_handler_result(idle, data()).
idle(info, wakeup, #data{worker_number = _WorkerNumber}) ->
    % TODO: Call the NIF to process pending parallel-hash work for WorkerNumber.
    keep_state_and_data;
idle(_EventType, _EventContent, _Data) ->
    keep_state_and_data.
