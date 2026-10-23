%%% % @format
-module(hash_valid).
-typing([eqwalizer]).
-export([
    fixed/0,
    native/0,
    public/0,
    tuple/0
]).

-spec fixed() -> Output when Output :: binary().
fixed() ->
    Initial = libdecaf:hash_init({sha3_256, 16}),
    libdecaf:hash_final(libdecaf:hash_update(Initial, <<"abc">>)).

-spec native() -> Output when Output :: binary().
native() ->
    Hash = libdecaf_nif:kmac128_hash_init(32, <<"key">>, <<"custom">>),
    _ = libdecaf_nif:hash_final(libdecaf_nif:hash_update(Hash, <<"abc">>)),
    Initial = libdecaf_nif:kmacxof256_xof_init(<<"key">>),
    State = libdecaf_nif:xof_absorb(Initial, <<"abc">>),
    {Next, First} = libdecaf_nif:xof_squeeze(State, 16),
    {_, Last} = libdecaf_nif:xof_squeeze(Next, 16),
    <<First/binary, Last/binary>>.

-spec public() -> Output when Output :: binary().
public() ->
    _ = libdecaf:hash({hopmac128, 32, <<"key">>}, <<"abc">>),
    _ = libdecaf:hash({parallelhash128, 32, 8}, <<"abc">>),
    _ = libdecaf:hash({shake128, 32}, <<"abc">>),
    _ = libdecaf:xof({keccakxof_128, 32}, <<"abc">>),
    _ = libdecaf:xof_init({cshake128, <<>>, <<"custom">>}),
    _ = libdecaf:xof_init({turboshake128, 31}),
    Initial = libdecaf:xof_init({kt256, <<"custom">>}),
    State = libdecaf:xof_absorb(Initial, <<"abc">>),
    {_, Output} = libdecaf:xof_squeeze(State, 32),
    Output.

-spec tuple() -> Output when Output :: binary().
tuple() ->
    _ = libdecaf:hash({tuplehash128, 32}, [<<"a">>, <<"bc">>]),
    Initial = libdecaf:xof_init({tuplehashxof128, <<"custom">>}),
    State = libdecaf:xof_absorb(Initial, [<<"a">>, <<"bc">>]),
    {_, Output} = libdecaf:xof_squeeze(State, 32),
    Output.
