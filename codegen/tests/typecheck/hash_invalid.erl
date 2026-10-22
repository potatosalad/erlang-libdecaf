%%% % @format
-module(hash_invalid).
-typing([eqwalizer]).
-export([
    algorithm/0,
    domain/0,
    fixed_state/0,
    xof_state/0
]).

-spec algorithm() -> libdecaf_nif:hash_xof_kt_state().
algorithm() ->
    libdecaf_nif:hash_xof_kt_init(shake128).

-spec domain() -> libdecaf_nif:hash_xof_turboshake_state().
domain() ->
    libdecaf_nif:hash_xof_turboshake_init(turboshake128, <<31>>).

-spec fixed_state() -> libdecaf_nif:hash_sha3_state().
fixed_state() ->
    State = libdecaf_nif:hash_sha2_init(sha2_512),
    libdecaf_nif:hash_sha3_update(State, <<"abc">>).

-spec xof_state() -> libdecaf_nif:hash_xof_sha3_state().
xof_state() ->
    State = libdecaf_nif:hash_xof_kt_init(kt128),
    libdecaf_nif:hash_xof_sha3_update(State, <<"abc">>).
