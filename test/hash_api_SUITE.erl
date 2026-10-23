%%% % @format
-module(hash_api_SUITE).
-moduledoc """
Fixed digest prefixes, default lengths, parameter tuples, and native dispatch.
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-export([
    all/0,
    fixed_hashes/1,
    defaults/1,
    parameters/1,
    exports/1,
    xof_one_shot/1,
    isolation/1
]).
all() -> [fixed_hashes, defaults, parameters, exports, xof_one_shot, isolation].

fixed_hashes(_) ->
    lists:foreach(
        fun({_Family, Type, Crypto, Maximum}) ->
            lists:foreach(
                fun(Input) ->
                    Expected =
                        case Crypto of
                            none -> libdecaf_nif:hash(Type, Input);
                            _ -> crypto:hash(Crypto, Input)
                        end,
                    lists:foreach(
                        fun(Module) ->
                            Expected = apply(libdecaf_nif, Type, [Input]),
                            Default = Module:hash_update(Module:hash_init(Type), [Input]),
                            Expected = Module:hash_final(Default),
                            lists:foreach(
                                fun(Length) ->
                                    Prefix = binary:part(Expected, 0, Length),
                                    Prefix = Module:hash({Type, Length}, [Input]),
                                    State0 = Module:hash_init({Type, Length}),
                                    State1 = Module:hash_update(State0, [Input]),
                                    Prefix = Module:hash_final(State1),
                                    Prefix = Module:hash_final(State1)
                                end,
                                [0, 1, Maximum]
                            ),
                            badarg(fun() -> Module:hash_init({Type, Maximum + 1}) end)
                        end,
                        [libdecaf, libdecaf_nif]
                    )
                end,
                [<<>>, <<"abc">>, binary:copy(<<42>>, 65537)]
            )
        end,
        [
            {sha2, sha2_512, sha512, 64},
            {sha3, sha3_224, sha3_224, 28},
            {sha3, sha3_256, sha3_256, 32},
            {sha3, sha3_384, sha3_384, 48},
            {sha3, sha3_512, sha3_512, 64},
            {keccak, keccak_224, none, 28},
            {keccak, keccak_256, none, 32},
            {keccak, keccak_384, none, 48},
            {keccak, keccak_512, none, 64}
        ]
    ),
    <<"4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45">> =
        binary:encode_hex(libdecaf:hash(keccak_256, <<"abc">>)).

defaults(_) ->
    lists:foreach(
        fun({_Family, Type, Length}) ->
            Output = libdecaf:hash(Type, <<"abc">>),
            Length = byte_size(Output),
            Output = libdecaf:hash({Type, Length}, <<"abc">>),
            Output = libdecaf:hash_final(libdecaf:hash_update(libdecaf:hash_init(Type), <<"abc">>))
        end,
        [{kt, kt128, 32}, {kt, kt256, 64}, {turboshake, turboshake128, 32}, {turboshake, turboshake256, 64}]
    ).

parameters(_) ->
    lists:foreach(
        fun(Module) ->
            A = Module:hash_init(keccak_256),
            B = Module:hash_init({keccak_256}),
            Output = Module:hash_final(A),
            Output = Module:hash_final(B),
            lists:foreach(
                fun({Type, _Name}) ->
                    Expected = Module:hash({Type, 32}, <<"abc">>),
                    State = Module:hash_update(Module:hash_init({Type, 32}), <<"abc">>),
                    Expected = Module:hash_final(State)
                end,
                [
                    {shake128, hash_sha3},
                    {shake256, hash_sha3},
                    {keccakxof_128, hash_keccak},
                    {keccakxof_256, hash_keccak}
                ]
            )
        end,
        [libdecaf, libdecaf_nif]
    ).

exports(_) ->
    Public = lists:sort(libdecaf:module_info(exports) -- [{module_info, 0}, {module_info, 1}]),
    Public = lists:sort([
        {hash, 2},
        {hash_init, 1},
        {hash_update, 2},
        {hash_final, 1},
        {xof, 3},
        {xof_init, 1},
        {xof_absorb, 2},
        {xof_squeeze, 2}
    ]),
    Native = libdecaf_nif:module_info(exports),
    false = lists:member({xof, 2}, Native),
    lists:foreach(
        fun(F) -> true = lists:member(F, Native) end,
        [
            {parallelhash128, 4},
            {parallelhash128_hash_init, 3},
            {parallelhashxof128, 4},
            {parallelhashxof128_xof_init, 2},
            {turboshake128_hash_init, 2},
            {turboshake128_xof_init, 1}
        ]
    ),
    false = lists:member({hash_init_parallelhash, 4}, Native),
    false = lists:member({parallelhash128_hash_update, 2}, Native).

xof_one_shot(_) ->
    lists:foreach(
        fun(Module) ->
            lists:foreach(
                fun(Length) ->
                    Expected = libdecaf_nif:kmacxof128(<<>>, Length, <<>>),
                    Expected = Module:xof({kmacxof128, <<>>}, <<>>, Length),
                    Initial = Module:xof_init({kmacxof128, <<>>}),
                    State = Module:xof_absorb(Initial, <<>>),
                    {_, Expected} = Module:xof_squeeze(State, Length)
                end,
                [0, 32, 65]
            )
        end,
        [libdecaf, libdecaf_nif]
    ).

isolation(_) ->
    lists:foreach(
        fun(Module) ->
            Hash = Module:hash_init({shake128, 32}),
            Xof = Module:xof_init(shake128),
            badarg(fun() -> Module:hash_update(Xof, <<>>) end),
            badarg(fun() -> Module:hash_final(Xof) end),
            badarg(fun() -> Module:xof_absorb(Hash, <<>>) end),
            badarg(fun() -> Module:xof_squeeze(Hash, 32) end),
            badarg(fun() -> Module:hash_final(make_ref()) end)
        end,
        [libdecaf, libdecaf_nif]
    ).

badarg(Fun) ->
    try Fun() of
        Value -> ct:fail({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.
