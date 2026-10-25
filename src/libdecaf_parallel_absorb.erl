%%% % @format
-module(libdecaf_parallel_absorb).
-moduledoc false.
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

%% OTP callbacks
-export([
    child_name/1,
    child_spec/1,
    start_link/3
]).
%% proc_lib callbacks
-export([
    init/3
]).

%%%=============================================================================
%%% OTP callbacks
%%%=============================================================================

-doc "Return the registered name for a router's native queue consumer.".
-spec child_name(RouterNumber) -> ChildName when
    RouterNumber :: libdecaf_parallel_router:router_number(), ChildName :: atom().
child_name(RouterNumber) ->
    _ = libdecaf_parallel_router:child_name(RouterNumber),
    binary_to_atom(<<"libdecaf_parallel_absorb_", (integer_to_binary(RouterNumber))/binary>>, utf8).

-doc "Return the dynamic child template for a router's absorb processes.".
-spec child_spec(RouterNumber) -> ChildSpec when
    RouterNumber :: libdecaf_parallel_router:router_number(), ChildSpec :: supervisor:child_spec().
child_spec(RouterNumber) ->
    #{
        id => ?MODULE,
        start => {?MODULE, start_link, [RouterNumber]},
        restart => temporary,
        shutdown => brutal_kill,
        type => worker,
        modules => [?MODULE]
    }.

-doc "Start an absorb process associated with a router and readiness token.".
-spec start_link(RouterNumber, RouterPid, Token) -> StartResult when
    RouterNumber :: libdecaf_parallel_router:router_number(),
    RouterPid :: pid(),
    Token :: reference(),
    StartResult :: {ok, pid()} | {error, term()}.
start_link(RouterNumber, RouterPid, Token) ->
    proc_lib:start_link(?MODULE, init, [RouterNumber, RouterPid, Token]).

%%%=============================================================================
%%% proc_lib callbacks
%%%=============================================================================

-doc false.
-spec init(RouterNumber, RouterPid, Token) -> Result when
    RouterNumber :: libdecaf_parallel_router:router_number(), RouterPid :: pid(), Token :: reference(), Result :: ok.
init(RouterNumber, RouterPid, Token) ->
    RouterMonitor = monitor(process, RouterPid),
    true = register(child_name(RouterNumber), self()),
    ok = proc_lib:init_ack({ok, self()}),
    RouterPid ! {absorb_ready, self(), Token},
    case libdecaf_nif:parallel_router_info() of
        #{queued := 0} -> ok;
        _ -> self() ! wakeup
    end,
    loop(RouterNumber, RouterPid, Token, RouterMonitor).

-spec loop(RouterNumber, RouterPid, Token, RouterMonitor) -> Result when
    RouterNumber :: libdecaf_parallel_router:router_number(),
    RouterPid :: pid(),
    Token :: reference(),
    RouterMonitor :: reference(),
    Result :: ok.
loop(RouterNumber, RouterPid, Token, RouterMonitor) ->
    receive
        wakeup ->
            work(RouterNumber, RouterPid, Token, false),
            loop(RouterNumber, RouterPid, Token, RouterMonitor);
        {wakeup, Token} ->
            work(RouterNumber, RouterPid, Token, true),
            loop(RouterNumber, RouterPid, Token, RouterMonitor);
        {absorb_rejected, Token} ->
            ok;
        {'DOWN', RouterMonitor, process, RouterPid, _Reason} ->
            ok
    end.

-spec work(RouterNumber, RouterPid, Token, Notify) -> Result when
    RouterNumber :: libdecaf_parallel_router:router_number(),
    RouterPid :: pid(),
    Token :: reference(),
    Notify :: boolean(),
    Result :: ok.
work(RouterNumber, RouterPid, Token, Notify0) ->
    Notify = coalesce(Token, Notify0),
    ok = libdecaf_nif:parallel_absorb(RouterNumber, application:get_env(libdecaf, parallel_absorb_rounds, 100)),
    case Notify of
        true ->
            RouterPid ! {absorb_idle, self(), Token},
            ok;
        false ->
            ok
    end.

-spec coalesce(Token, Notify) -> NewNotify when
    Token :: reference(), Notify :: boolean(), NewNotify :: boolean().
coalesce(Token, Notify) ->
    receive
        wakeup -> coalesce(Token, Notify);
        {wakeup, Token} -> coalesce(Token, true)
    after 0 -> Notify
    end.
