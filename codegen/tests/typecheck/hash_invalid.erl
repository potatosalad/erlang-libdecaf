%%% % @format
-module(hash_invalid).
-typing([eqwalizer]).
-export([
    algorithm/0,
    block_size/0,
    domain/0,
    fixed_state/0,
    kmac_algorithm/0,
    native_xof_state/0,
    public_algorithm/0,
    tuple_input/0
]).

-spec algorithm() -> State when State :: libdecaf_nif:xof_state().
algorithm() ->
    libdecaf_nif:xof_init_kt(shake128).

-spec block_size() -> State when State :: libdecaf:hash_state().
block_size() ->
    libdecaf:hash_init_parallelhash(parallelhash128, 32, <<8>>).

-spec domain() -> State when State :: libdecaf_nif:xof_state().
domain() ->
    libdecaf_nif:xof_init_turboshake(turboshake128, <<31>>).

-spec fixed_state() -> State when State :: libdecaf:hash_state().
fixed_state() ->
    State = libdecaf:xof_init_sha3(shake128),
    libdecaf:hash_update(State, <<"abc">>).

-spec kmac_algorithm() -> State when State :: libdecaf_nif:hash_state().
kmac_algorithm() ->
    libdecaf_nif:hash_init_kmac(kmacxof128, 32, <<"key">>).

-spec native_xof_state() -> State when State :: libdecaf_nif:xof_state().
native_xof_state() ->
    State = libdecaf_nif:hash_init_kt(kt128),
    libdecaf_nif:xof_absorb(State, <<"abc">>).

-spec public_algorithm() -> State when State :: libdecaf:xof_state().
public_algorithm() ->
    libdecaf:xof_init_kmac(kmac128, <<"key">>).

-spec tuple_input() -> Output when Output :: binary().
tuple_input() ->
    libdecaf:hash_tuplehash(tuplehash128, <<"flattened">>, 32).
