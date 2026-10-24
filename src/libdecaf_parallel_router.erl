%%% % @format
-module(libdecaf_parallel_router).
-moduledoc """
Parallel-work router with one prepared absorb process and one pending wakeup.

An absorb process is started asynchronously before work arrives. Sending
`wakeup` dispatches it. While it is working, further wakeups set a single
pending flag. When it exits, the router prepares a replacement and dispatches
it if that flag is set. Startup wakeups are coalesced in the same way.
Failed starts are retried after 250 milliseconds without restarting the router
or discarding its pending wakeup.

Routers hibernate after five idle seconds. Ready absorb processes wait for
work without occupying a dirty scheduler.

```erlang
{ok, _} = application:ensure_all_started(libdecaf),
#{names := [RouterName | _]} = libdecaf_nif:parallel_router_info(),
RouterName ! wakeup.
```
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
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
    starting/3,
    ready/3,
    working/3
]).

%% Records
-record(data, {
    router_number :: router_number(),
    absorb_sup :: atom(),
    starter_monitor :: reference() | undefined,
    token :: reference() | undefined,
    absorb_pid :: pid() | undefined,
    absorb_monitor :: reference() | undefined,
    pending = false :: boolean()
}).

%% Types
-type data() :: #data{}.
-doc "One-based index into the native router-name list.".
-type router_number() :: pos_integer().

-export_type([
    router_number/0
]).

%%%=============================================================================
%%% OTP callbacks
%%%=============================================================================

-doc "Return an existing router name allocated by the NIF.".
-spec child_name(RouterNumber) -> ChildName when RouterNumber :: router_number(), ChildName :: atom().
child_name(RouterNumber) when is_integer(RouterNumber), RouterNumber >= 1 ->
    #{names := Names} = libdecaf_nif:parallel_router_info(),
    lists:nth(RouterNumber, Names).

-doc "Return the numbered router's child specification.".
-spec child_spec(RouterNumber) -> ChildSpec when
    RouterNumber :: router_number(), ChildSpec :: supervisor:child_spec().
child_spec(RouterNumber) ->
    ChildName = child_name(RouterNumber),
    #{
        id => ChildName,
        start => {?MODULE, start_link, [{local, ChildName}, RouterNumber]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [?MODULE]
    }.

-doc "Start a router with five-second idle hibernation.".
-spec start_link(ServerName, RouterNumber) -> StartResult when
    ServerName :: gen_statem:server_name(), RouterNumber :: router_number(), StartResult :: gen_statem:start_ret().
start_link(ServerName, RouterNumber) ->
    gen_statem:start_link(ServerName, ?MODULE, RouterNumber, [{hibernate_after, 5000}]).

%%%=============================================================================
%%% gen_statem callbacks
%%%=============================================================================

-doc false.
-spec callback_mode() -> CallbackMode when CallbackMode :: gen_statem:callback_mode_result().
callback_mode() ->
    [state_functions].

-doc false.
-spec init(RouterNumber) -> InitResult when
    RouterNumber :: router_number(), InitResult :: {ok, starting, data(), [gen_statem:action()]}.
init(RouterNumber) ->
    Data = #data{router_number = RouterNumber, absorb_sup = libdecaf_parallel_absorb_sup:child_name(RouterNumber)},
    {ok, starting, Data, [{next_event, internal, start_absorb}]}.

%%%=============================================================================
%%% gen_statem states
%%%=============================================================================

-doc false.
-spec starting(EventType, EventContent, Data) -> HandleEventResult when
    EventType :: gen_statem:event_type(),
    EventContent :: dynamic(),
    Data :: data(),
    HandleEventResult :: gen_statem:event_handler_result(starting | ready | working, data()).
starting(internal, start_absorb, Data) ->
    start_absorb(Data);
starting(state_timeout, retry_absorb, Data) ->
    start_absorb(Data);
starting(info, wakeup, #data{pending = true}) ->
    keep_state_and_data;
starting(info, wakeup, Data) ->
    {keep_state, Data#data{pending = true}};
starting(info, {absorb_ready, Pid, Token}, Data0 = #data{token = Token}) when is_pid(Pid) ->
    Data = monitor_absorb(Pid, Data0),
    case Data#data.pending of
        true -> start_work(Data);
        false -> {next_state, ready, Data}
    end;
starting(EventType, EventContent, Data) ->
    handle_event(EventType, EventContent, Data).

-doc false.
-spec ready(EventType, EventContent, Data) -> HandleEventResult when
    EventType :: gen_statem:event_type(),
    EventContent :: dynamic(),
    Data :: data(),
    HandleEventResult :: gen_statem:event_handler_result(starting | working, data()).
ready(info, wakeup, Data) ->
    start_work(Data);
ready(EventType, EventContent, Data) ->
    handle_event(EventType, EventContent, Data).

-doc false.
-spec working(EventType, EventContent, Data) -> HandleEventResult when
    EventType :: gen_statem:event_type(),
    EventContent :: dynamic(),
    Data :: data(),
    HandleEventResult :: gen_statem:event_handler_result(starting, data()).
working(info, wakeup, #data{pending = true}) ->
    keep_state_and_data;
working(info, wakeup, Data) ->
    {keep_state, Data#data{pending = true}};
working(EventType, EventContent, Data) ->
    handle_event(EventType, EventContent, Data).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-spec handle_event(EventType, EventContent, Data) -> HandleEventResult when
    EventType :: gen_statem:event_type(),
    EventContent :: dynamic(),
    Data :: data(),
    HandleEventResult :: gen_statem:event_handler_result(starting, data()).
handle_event(
    info, {'DOWN', Monitor, process, _Starter, {absorb_started, Pid}}, Data = #data{starter_monitor = Monitor}
) when
    is_reference(Monitor), is_pid(Pid)
->
    % Readiness can arrive before or after the starter's DOWN signal.
    {keep_state, monitor_absorb(Pid, Data#data{starter_monitor = undefined})};
handle_event(
    info, {'DOWN', Monitor, process, _Starter, _Reason}, Data = #data{starter_monitor = Monitor, absorb_pid = undefined}
) when
    is_reference(Monitor)
->
    {keep_state, Data#data{starter_monitor = undefined}, [{state_timeout, 250, retry_absorb}]};
handle_event(info, {'DOWN', Monitor, process, _Starter, _Reason}, Data = #data{starter_monitor = Monitor}) when
    is_reference(Monitor)
->
    % A registered child can outlive a failed starter; keep using that child.
    {keep_state, Data#data{starter_monitor = undefined}};
handle_event(
    info, {'DOWN', Monitor, process, Pid, _Reason}, Data = #data{absorb_monitor = Monitor, absorb_pid = Pid}
) when
    is_reference(Monitor)
->
    {next_state, starting, Data#data{absorb_pid = undefined, absorb_monitor = undefined}, [
        {next_event, internal, start_absorb}
    ]};
handle_event(info, {absorb_ready, Pid, Token}, _Data) when is_pid(Pid), is_reference(Token) ->
    % A late registration from an abandoned attempt must not leave an idle orphan.
    Pid ! {absorb_rejected, Token},
    keep_state_and_data;
handle_event({call, From}, _Request, _Data) ->
    {keep_state_and_data, [{reply, From, ignored}]};
handle_event(_EventType, _EventContent, _Data) ->
    keep_state_and_data.

-spec start_absorb(Data) -> HandleEventResult when
    Data :: data(), HandleEventResult :: gen_statem:event_handler_result(starting, data()).
start_absorb(Data = #data{absorb_sup = AbsorbSup}) ->
    Router = self(),
    Token = make_ref(),
    % A monitored helper keeps both blocking supervisor calls and startup failures
    % outside the router. Its result travels in DOWN so a helper crash is handled too.
    try
        spawn_monitor(fun() ->
            case supervisor:start_child(AbsorbSup, [Router, Token]) of
                {ok, Pid} -> exit({absorb_started, Pid});
                Result -> exit({absorb_start_failed, Result})
            end
        end)
    of
        {_Pid, Monitor} ->
            {keep_state, Data#data{token = Token, starter_monitor = Monitor}}
    catch
        error:system_limit ->
            {keep_state, Data#data{token = Token, starter_monitor = undefined}, [{state_timeout, 250, retry_absorb}]}
    end.

-spec monitor_absorb(Pid, Data) -> NewData when Pid :: pid(), Data :: data(), NewData :: data().
monitor_absorb(Pid, Data = #data{absorb_pid = Pid}) ->
    Data;
monitor_absorb(Pid, Data = #data{absorb_pid = undefined}) ->
    Data#data{absorb_pid = Pid, absorb_monitor = monitor(process, Pid)}.

-spec start_work(Data) -> HandleEventResult when
    Data :: data(), HandleEventResult :: {next_state, working, data()}.
start_work(Data = #data{absorb_pid = Pid, token = Token}) when is_pid(Pid), is_reference(Token) ->
    Pid ! {wakeup, Token},
    {next_state, working, Data#data{pending = false}}.
