%%% % @format
-module(libdecaf_parallel_routers_sup).
-moduledoc false.
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-24", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

-behaviour(supervisor).

%% OTP callbacks
-export([
    child_spec/0,
    child_specs/0,
    start_link/0,
    sup_flags/0
]).
%% supervisor callbacks
-export([
    init/1
]).

%%%=============================================================================
%%% OTP callbacks
%%%=============================================================================

-doc "Return the parallel router supervisor's child specification.".
-spec child_spec() -> ChildSpec when ChildSpec :: supervisor:child_spec().
child_spec() ->
    #{
        id => ?MODULE,
        start => {?MODULE, start_link, []},
        restart => permanent,
        shutdown => infinity,
        type => supervisor,
        modules => [?MODULE]
    }.

-doc "Return child specifications in native router-number order.".
-spec child_specs() -> ChildSpecs when ChildSpecs :: [supervisor:child_spec()].
child_specs() ->
    #{count := RouterCount} = libdecaf_nif:parallel_router_info(),
    [libdecaf_parallel_router_sup:child_spec(RouterNumber) || RouterNumber <- lists:seq(1, RouterCount)].

-doc "Start the locally registered parallel router supervisor.".
-spec start_link() -> StartResult when StartResult :: supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, {}).

-doc "Return the independent-router restart policy.".
-spec sup_flags() -> SupFlags when SupFlags :: supervisor:sup_flags().
sup_flags() ->
    #{
        strategy => one_for_one,
        intensity => 1,
        period => 5
    }.

%%%=============================================================================
%%% supervisor callbacks
%%%=============================================================================

-doc false.
-spec init(Args) -> InitResult when
    Args :: {},
    InitResult :: {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init({}) ->
    {ok, {sup_flags(), child_specs()}}.
