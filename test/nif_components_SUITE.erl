%%% % @format
-module(nif_components_SUITE).
-moduledoc """
Exercise component resources directly through the native interface.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    csprng/1,
    keypairs/1,
    upgrade/1
]).

all() ->
    [keypairs, csprng, upgrade].

keypairs(_) ->
    lists:foreach(
        fun({Curve, Bytes, Context}) ->
            Secret = binary:copy(<<7>>, Bytes),
            Keypair = call(Curve, "_derive_keypair", [Secret]),
            Secret = call(Curve, "_keypair_extract_private_key", [Keypair]),
            Public = call(Curve, "_keypair_extract_public_key", [Keypair]),
            Public = call(Curve, "_derive_public_key", [Secret]),
            Signature = call(Curve, "_keypair_sign", [Keypair, <<"message">>, 0, Context]),
            Signature = call(Curve, "_sign", [Secret, Public, <<"message">>, 0, Context]),
            true = call(Curve, "_verify", [Signature, Public, <<"message">>, 0, Context]),
            false = call(Curve, "_verify", [Signature, Public, <<"changed">>, 0, Context]),
            Prehashed = call(Curve, "_keypair_sign_prehash", [Keypair, <<"message">>, <<>>]),
            Prehashed = call(Curve, "_sign_prehash", [Secret, Public, <<"message">>, <<>>]),
            true = call(Curve, "_verify_prehash", [Prehashed, Public, <<"message">>, <<>>])
        end,
        [{ed25519, 32, no_context}, {ed448, 57, <<>>}]
    ).

csprng(_) ->
    Initial = libdecaf_nif:spongerng_csprng_init_from_buffer(<<>>, true),
    Expected = binary:decode_hex(<<"2ED664354AA87699BE93C3B62715A256">>),
    {Next, Expected} = libdecaf_nif:spongerng_csprng_next(Initial, 16),
    {_, Expected} = libdecaf_nif:spongerng_csprng_next(Initial, 16),
    {_, Following} = libdecaf_nif:spongerng_csprng_next(Next, 16),
    true = Following =/= Expected,
    Stirred = libdecaf_nif:spongerng_csprng_stir(Initial, [<<"seed">>]),
    {_, Changed} = libdecaf_nif:spongerng_csprng_next(Stirred, 16),
    true = Changed =/= Expected.

upgrade(_) ->
    Keys = [
        {Curve, call(Curve, "_derive_keypair", [binary:copy(<<7>>, Bytes)])}
     || {Curve, Bytes} <- [{ed25519, 32}, {ed448, 57}]
    ],
    PublicKeys = [{Curve, call(Curve, "_keypair_extract_public_key", [Key])} || {Curve, Key} <- Keys],
    Random = libdecaf_nif:spongerng_csprng_init_from_buffer(<<"seed">>, true),
    {_, Expected} = libdecaf_nif:spongerng_csprng_next(Random, 32),
    {libdecaf_nif, Beam, Filename} = code:get_object_code(libdecaf_nif),
    {module, libdecaf_nif} = code:load_binary(libdecaf_nif, Filename, Beam),
    PublicKeys = [{Curve, call(Curve, "_keypair_extract_public_key", [Key])} || {Curve, Key} <- Keys],
    {_, Expected} = libdecaf_nif:spongerng_csprng_next(Random, 32),
    keypairs([]),
    csprng([]).

call(Component, Suffix, Arguments) ->
    apply(libdecaf_nif, list_to_atom(atom_to_list(Component) ++ Suffix), Arguments).
