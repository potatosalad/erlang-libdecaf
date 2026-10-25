%%% % @format
-module(libdecaf_parallel_router_sup).
-moduledoc false.
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

-behaviour(supervisor).

%% OTP callbacks
-export([
    child_name/1,
    child_spec/1,
    child_specs/1,
    start_link/2,
    sup_flags/0
]).
%% supervisor callbacks
-export([
    init/1
]).

%%%=============================================================================
%%% OTP callbacks
%%%=============================================================================

-doc "Return the registered supervisor name for a native router number.".
-spec child_name(RouterNumber) -> ChildName when
    RouterNumber :: libdecaf_parallel_router:router_number(), ChildName :: atom().
child_name(RouterNumber) ->
    RouterName = libdecaf_parallel_router:child_name(RouterNumber),
    erlang:binary_to_atom(<<(erlang:atom_to_binary(RouterName))/binary, "_sup">>, utf8).

-doc "Return the child specification for a router's supervision tree.".
-spec child_spec(RouterNumber) -> ChildSpec when
    RouterNumber :: libdecaf_parallel_router:router_number(), ChildSpec :: supervisor:child_spec().
child_spec(RouterNumber) ->
    ChildName = child_name(RouterNumber),
    #{
        id => ChildName,
        start => {?MODULE, start_link, [{local, ChildName}, RouterNumber]},
        restart => permanent,
        shutdown => infinity,
        type => supervisor,
        modules => [?MODULE]
    }.

-doc "Return the absorb supervisor followed by its router.".
-spec child_specs(RouterNumber) -> ChildSpecs when
    RouterNumber :: libdecaf_parallel_router:router_number(), ChildSpecs :: [supervisor:child_spec()].
child_specs(RouterNumber) ->
    [libdecaf_parallel_absorb_sup:child_spec(RouterNumber), libdecaf_parallel_router:child_spec(RouterNumber)].

-doc "Start a locally registered router supervisor.".
-spec start_link(ServerName, RouterNumber) -> StartResult when
    ServerName :: supervisor:sup_name(),
    RouterNumber :: libdecaf_parallel_router:router_number(),
    StartResult :: supervisor:startlink_ret().
start_link(ServerName, RouterNumber) ->
    supervisor:start_link(ServerName, ?MODULE, RouterNumber).

-doc "Return the ordered restart policy.".
-spec sup_flags() -> SupFlags when SupFlags :: supervisor:sup_flags().
sup_flags() ->
    #{strategy => rest_for_one, intensity => 1, period => 5}.

%%%=============================================================================
%%% supervisor callbacks
%%%=============================================================================

-doc false.
-spec init(RouterNumber) -> InitResult when
    RouterNumber :: libdecaf_parallel_router:router_number(),
    InitResult :: {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(RouterNumber) ->
    {ok, {sup_flags(), child_specs(RouterNumber)}}.
