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
    isolation/1
]).
all() -> [fixed_hashes, defaults, parameters, exports, isolation].

fixed_hashes(_) ->
    lists:foreach(
        fun({Family, Type, Crypto, Maximum}) ->
            lists:foreach(
                fun(Input) ->
                    Name = list_to_atom("hash_" ++ atom_to_list(Family)),
                    Expected =
                        case Crypto of
                            none -> apply(libdecaf_nif, Name, [Type, Input]);
                            _ -> crypto:hash(Crypto, Input)
                        end,
                    lists:foreach(
                        fun(Module) ->
                            Expected = apply(Module, Name, [Type, Input]),
                            Default = Module:hash_update(Module:hash_init(Type), [Input]),
                            Expected = Module:hash_final(Default),
                            lists:foreach(
                                fun(Length) ->
                                    Prefix = binary:part(Expected, 0, Length),
                                    Prefix = apply(Module, Name, [Type, [Input], Length]),
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
        binary:encode_hex(libdecaf:hash_keccak(keccak_256, <<"abc">>)).

defaults(_) ->
    lists:foreach(
        fun({Family, Type, Length}) ->
            Name = list_to_atom("hash_" ++ atom_to_list(Family)),
            Init = list_to_atom("hash_init_" ++ atom_to_list(Family)),
            Output = apply(libdecaf, Name, [Type, <<"abc">>]),
            Length = byte_size(Output),
            Output = apply(libdecaf, Name, [Type, <<"abc">>, Length]),
            Output = libdecaf:hash_final(libdecaf:hash_update(apply(libdecaf, Init, [Type]), <<"abc">>))
        end,
        [{kt, kt128, 32}, {kt, kt256, 64}, {turboshake, turboshake128, 32}, {turboshake, turboshake256, 64}]
    ).

parameters(_) ->
    lists:foreach(
        fun(Module) ->
            A = Module:hash_init_keccak(keccak_256),
            B = Module:hash_init({keccak_256}),
            Output = Module:hash_final(A),
            Output = Module:hash_final(B),
            lists:foreach(
                fun({Type, Name}) ->
                    Expected = apply(Module, Name, [Type, <<"abc">>, 32]),
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
    lists:foreach(
        fun(Module) ->
            Exports = Module:module_info(exports),
            lists:foreach(
                fun(Function) -> true = lists:member(Function, Exports) end,
                [
                    {hash_init, 1},
                    {hash_update, 2},
                    {hash_final, 1},
                    {xof_init, 1},
                    {xof_absorb, 2},
                    {xof_squeeze, 2},
                    {hash_init_hopmac, 3},
                    {xof_init_hopmac, 2}
                ]
            ),
            false = lists:member({hash_final, 2}, Exports),
            false = lists:member({xof_kt_final, 3}, Exports),
            false = lists:member({xof_sha3_update, 2}, Exports)
        end,
        [libdecaf, libdecaf_nif]
    ).

isolation(_) ->
    lists:foreach(
        fun(Module) ->
            Hash = Module:hash_init_sha3(shake128, 32),
            Xof = Module:xof_init_sha3(shake128),
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
