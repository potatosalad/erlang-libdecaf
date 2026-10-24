%%% % @format
-module(public_key_api_SUITE).
-moduledoc """
High-level EdDSA/ECDH key formats, dispatch, streaming, and failure contracts.
Published vectors also exercise this API in cfrg_SUITE.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    keypairs/1,
    key_formats/1,
    contexts/1,
    streaming/1,
    rejected_peers/1,
    mismatched_keys/1,
    invalid_arguments/1,
    metadata/1
]).

all() ->
    [keypairs, key_formats, contexts, streaming, rejected_peers, mismatched_keys, invalid_arguments, metadata].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.

end_per_suite(_) -> ok.

keypairs(_) ->
    lists:foreach(
        fun({Algorithm, Bytes}) ->
            Secret = crypto:strong_rand_bytes(Bytes),
            KP = libdecaf:eddsa_keypair(Algorithm, Secret),
            {Public, Secret} = libdecaf:eddsa_keypair_extract(KP),
            Public = libdecaf:eddsa_keypair_extract_public_key(KP),
            Secret = libdecaf:eddsa_keypair_extract_secret_key(KP),
            Bytes = byte_size(Public),
            KP2 = libdecaf:eddsa_keypair(Algorithm),
            Signature = libdecaf:eddsa_sign({Algorithm, KP2}, <<>>),
            true = libdecaf:eddsa_verify({Algorithm, KP2}, Signature, [])
        end,
        [{ed25519, 32}, {ed448, 57}]
    ),
    lists:foreach(
        fun({Algorithm, Bytes}) ->
            Secret = crypto:strong_rand_bytes(Bytes),
            KP = libdecaf:ecdh_keypair(Algorithm, Secret),
            {Public, Secret} = libdecaf:ecdh_keypair_extract(KP),
            Public = libdecaf:ecdh_keypair_extract_public_key(KP),
            Secret = libdecaf:ecdh_keypair_extract_secret_key(KP),
            Bytes = byte_size(Public),
            KP2 = libdecaf:ecdh_keypair(Algorithm),
            Shared = libdecaf:ecdh_shared_secret(Algorithm, KP, KP2),
            Shared = libdecaf:ecdh_shared_secret(Algorithm, KP2, KP),
            Bytes = byte_size(Shared)
        end,
        [{x25519, 32}, {x448, 56}]
    ).

key_formats(_) ->
    lists:foreach(
        fun({Algorithm, Curve, Bytes, Variants}) ->
            Seed = binary:copy(<<7>>, Bytes),
            KP = libdecaf:eddsa_keypair(Algorithm, Seed),
            {Public, Seed} = libdecaf:eddsa_keypair_extract(KP),
            {Public, Encoded} = Curve:eddsa_keypair(Seed),
            lists:foreach(
                fun(Variant) ->
                    Expected = libdecaf:eddsa_sign({Variant, KP}, <<"message">>),
                    lists:foreach(
                        fun(Key) -> Expected = libdecaf:eddsa_sign({Variant, Key}, [<<"mess">>, "age"]) end,
                        [Seed, Encoded, {Public, Seed}, {Public, Encoded}]
                    ),
                    lists:foreach(
                        fun(Key) -> true = libdecaf:eddsa_verify({Variant, Key}, Expected, [<<"message">>]) end,
                        [Public, KP, {Public, Seed}, {Public, Encoded}]
                    )
                end,
                Variants
            )
        end,
        [
            {ed25519, libdecaf_curve25519, 32, [ed25519, ed25519ctx, ed25519ph]},
            {ed448, libdecaf_curve448, 57, [ed448, ed448ph]}
        ]
    ),
    lists:foreach(
        fun(Algorithm) ->
            A = libdecaf:ecdh_keypair(Algorithm),
            B = libdecaf:ecdh_keypair(Algorithm),
            {AP, AS} = libdecaf:ecdh_keypair_extract(A),
            {BP, BS} = libdecaf:ecdh_keypair_extract(B),
            Expected = libdecaf:ecdh_shared_secret(Algorithm, AS, BP),
            lists:foreach(
                fun({Secret, Public}) -> Expected = libdecaf:ecdh_shared_secret(Algorithm, Secret, Public) end,
                [{A, B}, {A, BP}, {AS, B}, {{AP, AS}, B}, {A, {BP, BS}}, {{AP, AS}, {BP, BS}}]
            )
        end,
        [x25519, x448]
    ).

contexts(_) ->
    K255 = libdecaf:eddsa_keypair(ed25519),
    K448 = libdecaf:eddsa_keypair(ed448),
    lists:foreach(
        fun({Variant, Key}) ->
            Empty = call(eddsa_sign, [{Variant, Key}, <<"message">>]),
            Empty = call(eddsa_sign, [{Variant, Key, <<>>}, <<"message">>]),
            Context = binary:copy(<<42>>, 255),
            Signature = call(eddsa_sign, [{Variant, Key, Context}, <<"message">>]),
            true = call(eddsa_verify, [{Variant, Key, Context}, Signature, <<"message">>]),
            false = call(eddsa_verify, [{Variant, Key}, Signature, <<"message">>]),
            false = call(eddsa_verify, [{Variant, Key, <<"other">>}, Signature, <<"message">>]),
            false = call(eddsa_verify, [{Variant, Key, Context}, Signature, <<"other">>])
        end,
        [{ed25519ctx, K255}, {ed25519ph, K255}, {ed448, K448}, {ed448ph, K448}]
    ),
    Pure = call(eddsa_sign, [{ed25519, K255}, <<"message">>]),
    false = call(eddsa_verify, [{ed25519ctx, K255}, Pure, <<"message">>]),
    false = call(eddsa_verify, [{ed25519ph, K255}, Pure, <<"message">>]).

streaming(_) ->
    lists:foreach(
        fun({Algorithm, Variant}) ->
            KP = libdecaf:eddsa_keypair(Algorithm),
            {Public, Seed} = libdecaf:eddsa_keypair_extract(KP),
            Encoded = <<Seed/binary, Public/binary>>,
            Chunks = [<<>>, [<<"start">>, "-"], binary:copy(<<42>>, 60001), <<"end">>],
            Message = iolist_to_binary(Chunks),
            Context = <<"streaming/v1">>,
            Expected = libdecaf:eddsa_sign({Variant, KP, Context}, Message),
            lists:foreach(
                fun(Key) ->
                    S0 = libdecaf:eddsa_sign_init({Variant, Key, Context}),
                    S1 = lists:foldl(fun(Chunk, S) -> libdecaf:eddsa_sign_update(S, Chunk) end, S0, Chunks),
                    Expected = libdecaf:eddsa_sign_final(S1),
                    Expected = libdecaf:eddsa_sign_final(S1),
                    Empty = libdecaf:eddsa_sign({Variant, Key, Context}, <<>>),
                    Empty = libdecaf:eddsa_sign_final(S0),
                    Branch = libdecaf:eddsa_sign_update(S0, <<"branch">>),
                    BranchSig = libdecaf:eddsa_sign({Variant, Key, Context}, <<"branch">>),
                    BranchSig = libdecaf:eddsa_sign_final(Branch)
                end,
                [KP, Seed, Encoded, {Public, Seed}, {Public, Encoded}]
            ),
            lists:foreach(
                fun(Key) ->
                    V0 = libdecaf:eddsa_verify_init({Variant, Key, Context}, Expected),
                    V1 = lists:foldl(fun(Chunk, V) -> libdecaf:eddsa_verify_update(V, Chunk) end, V0, Chunks),
                    true = libdecaf:eddsa_verify_final(V1),
                    true = libdecaf:eddsa_verify_final(V1),
                    false = libdecaf:eddsa_verify_final(V0),
                    badarg(fun() -> call(eddsa_sign_final, [V1]) end),
                    badarg(fun() -> call(eddsa_sign_update, [V1, []]) end)
                end,
                [Public, KP, {Public, Seed}, {Public, Encoded}]
            ),
            S = libdecaf:eddsa_sign_init({Variant, KP}),
            EmptySignature = libdecaf:eddsa_sign({Variant, KP}, <<>>),
            EmptySignature = libdecaf:eddsa_sign_final(S),
            true = libdecaf:eddsa_verify_final(libdecaf:eddsa_verify_init({Variant, KP}, EmptySignature)),
            badarg(fun() -> call(eddsa_verify_final, [S]) end),
            badarg(fun() -> call(eddsa_verify_update, [S, []]) end)
        end,
        [{ed25519, ed25519ph}, {ed448, ed448ph}]
    ).

rejected_peers(_) ->
    lists:foreach(
        fun({Algorithm, Bytes}) ->
            Key = libdecaf:ecdh_keypair(Algorithm),
            lists:foreach(
                fun(U) ->
                    Peer = <<U:(Bytes * 8)/little>>,
                    error = libdecaf:ecdh_shared_secret(Algorithm, Key, Peer)
                end,
                [0, 1]
            )
        end,
        [{x25519, 32}, {x448, 56}]
    ).

mismatched_keys(_) ->
    lists:foreach(
        fun({Algorithm, Variant}) ->
            A = libdecaf:eddsa_keypair(Algorithm),
            B = libdecaf:eddsa_keypair(Algorithm),
            {AP, AS} = libdecaf:eddsa_keypair_extract(A),
            {BP, BS} = libdecaf:eddsa_keypair_extract(B),
            Signature = libdecaf:eddsa_sign({Variant, A}, <<"message">>),
            lists:foreach(
                fun(Key) ->
                    badarg(fun() -> call(eddsa_sign, [{Variant, Key}, <<"message">>]) end),
                    badarg(fun() -> call(eddsa_sign_init, [{Variant, Key}]) end)
                end,
                [<<AS/binary, BP/binary>>, {BP, AS}, {AP, <<AS/binary, BP/binary>>}, {AP, <<BS/binary, AP/binary>>}]
            ),
            badarg(fun() -> call(eddsa_verify, [{Variant, {BP, AS}}, Signature, <<"message">>]) end),
            badarg(fun() -> call(eddsa_verify_init, [{Variant, {BP, AS}}, Signature]) end)
        end,
        [{ed25519, ed25519ph}, {ed448, ed448ph}]
    ),
    K255 = libdecaf:eddsa_keypair(ed25519),
    K448 = libdecaf:eddsa_keypair(ed448),
    badarg(fun() -> call(eddsa_sign, [{ed448, K255}, <<>>]) end),
    badarg(fun() -> call(eddsa_sign, [{ed25519, K448}, <<>>]) end),
    badarg(fun() -> call(eddsa_sign_init, [{ed448ph, K255}]) end),
    badarg(fun() -> call(eddsa_sign_init, [{ed25519ph, K448}]) end),
    X255 = libdecaf:ecdh_keypair(x25519),
    X448 = libdecaf:ecdh_keypair(x448),
    badarg(fun() -> call(ecdh_shared_secret, [x25519, X448, X255]) end),
    badarg(fun() -> call(ecdh_shared_secret, [x448, X448, X255]) end).

invalid_arguments(_) ->
    KP = libdecaf:eddsa_keypair(ed25519),
    Signature = libdecaf:eddsa_sign({ed25519ph, KP}, <<>>),
    lists:foreach(
        fun(Parameters) ->
            badarg(fun() -> call(eddsa_sign, [Parameters, <<>>]) end),
            badarg(fun() -> call(eddsa_verify, [Parameters, Signature, <<>>]) end),
            badarg(fun() -> call(eddsa_sign_init, [Parameters]) end),
            badarg(fun() -> call(eddsa_verify_init, [Parameters, Signature]) end)
        end,
        [
            bogus,
            {unknown, KP},
            {ed25519, KP, <<>>},
            {ed25519ctx, KP, no_context},
            {ed25519ph, KP, []},
            {ed25519ph, KP, binary:copy(<<0>>, 256)},
            {ed25519, <<>>},
            {ed25519ph, make_ref()}
        ]
    ),
    lists:foreach(fun(Variant) -> badarg(fun() -> call(eddsa_sign_init, [{Variant, KP}]) end) end, [
        ed25519, ed25519ctx, ed448
    ]),
    badarg(fun() -> call(eddsa_verify_init, [{ed25519, KP}, Signature]) end),
    badarg(fun() -> call(eddsa_sign, [{ed25519, KP}, [256]]) end),
    badarg(fun() -> call(eddsa_verify, [{ed25519ph, KP}, <<>>, <<>>]) end),
    badarg(fun() -> call(eddsa_sign_update, [make_ref(), <<>>]) end),
    badarg(fun() -> call(eddsa_verify_final, [make_ref()]) end),
    badarg(fun() -> call(eddsa_keypair, [ed25519ph]) end),
    badarg(fun() -> call(eddsa_keypair, [ed448, <<0:256>>]) end),
    badarg(fun() -> call(eddsa_keypair_extract, [make_ref()]) end),
    badarg(fun() -> call(ecdh_keypair, [ed25519]) end),
    badarg(fun() -> call(ecdh_keypair, [x448, <<0:256>>]) end),
    badarg(fun() -> call(ecdh_keypair_extract, [{<<>>, <<>>}]) end),
    badarg(fun() -> call(ecdh_shared_secret, [x25519, <<>>, <<0:256>>]) end),
    badarg(fun() -> call(ecdh_shared_secret, [unknown, <<>>, <<>>]) end).

metadata(_) ->
    {ok, {docs_v1, _, erlang, _, _, _, Entries}} = code:get_doc(libdecaf),
    Exports = [
        {Name, Arity}
     || {Name, Arity} <- libdecaf:module_info(exports),
        lists:prefix("ecdh_", atom_to_list(Name)) orelse lists:prefix("eddsa_", atom_to_list(Name))
    ],
    19 = length(Exports),
    lists:foreach(
        fun({Name, Arity}) ->
            {{function, Name, Arity}, _, [_ | _], Docs, Metadata} = lists:keyfind({function, Name, Arity}, 1, Entries),
            true = is_binary(maps:get(<<"en">>, Docs)),
            false = maps:is_key(deprecated, Metadata)
        end,
        Exports
    ).

badarg(Fun) ->
    try Fun() of
        _ -> ct:fail(expected_badarg)
    catch
        error:badarg -> ok;
        error:{badarg, _} -> ok;
        error:{badarg, _, _} -> ok
    end.

% Runtime rejection cases intentionally pass values outside the public typespecs.
call(Name, Arguments) ->
    erlang:apply(libdecaf, Name, Arguments).
