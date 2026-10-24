%%% % @format
-module(libdecaf_parallel_absorb).
-moduledoc """
Single-use parallel absorb process, started with `proc_lib`.

Registers its readiness with its router, then waits for that router's work
message. The placeholder NIF sleeps for one second on a dirty CPU scheduler;
after it returns the process exits normally. An unused process exits if its
router dies. Each process belongs to a temporary supervised child.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

%% OTP callbacks
-export([
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
init(_RouterNumber, RouterPid, Token) ->
    RouterMonitor = monitor(process, RouterPid),
    ok = proc_lib:init_ack({ok, self()}),
    RouterPid ! {absorb_ready, self(), Token},
    receive
        {wakeup, Token} ->
            libdecaf_nif:parallel_absorb();
        {absorb_rejected, Token} ->
            ok;
        {'DOWN', RouterMonitor, process, RouterPid, _Reason} ->
            ok
    end.
