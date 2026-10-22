%%% % @format
-module(hash_valid).
-typing([eqwalizer]).
-export([
    cshake/0,
    fixed/0,
    kt/0,
    shake/0,
    turboshake/0
]).

-spec cshake() -> binary().
cshake() ->
    Initial = libdecaf_nif:hash_xof_cshake_init(cshake128, <<>>, <<"example">>),
    State = libdecaf_nif:hash_xof_cshake_update(Initial, <<"abc">>),
    libdecaf_nif:hash_xof_cshake_final(State, 32).

-spec fixed() -> binary().
fixed() ->
    Initial = libdecaf_nif:hash_sha3_init(sha3_256),
    State = libdecaf_nif:hash_sha3_update(Initial, <<"abc">>),
    libdecaf_nif:hash_sha3_final(State).

-spec kt() -> binary().
kt() ->
    Initial = libdecaf_nif:hash_xof_kt_init(kt128),
    State = libdecaf_nif:hash_xof_kt_update(Initial, <<"abc">>),
    libdecaf_nif:hash_xof_kt_final(State, 32, <<"example">>).

-spec shake() -> binary().
shake() ->
    Initial = libdecaf_nif:hash_xof_sha3_init(shake128),
    State = libdecaf_nif:hash_xof_sha3_update(Initial, <<"abc">>),
    libdecaf_nif:hash_xof_sha3_final(State, 32).

-spec turboshake() -> binary().
turboshake() ->
    Initial = libdecaf_nif:hash_xof_turboshake_init(turboshake128, 31),
    State = libdecaf_nif:hash_xof_turboshake_update(Initial, <<"abc">>),
    libdecaf_nif:hash_xof_turboshake_final(State, 32).
