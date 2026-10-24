%%% % @format
-module(nif_components_SUITE).
-compile(warn_missing_spec_all).
-moduledoc """
Exercise component resources directly through the native interface.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    csprng/1,
    key_exchange/1,
    keypairs/1,
    prime_order_groups/1,
    upgrade/1
]).

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [keypairs, key_exchange, csprng, prime_order_groups, upgrade].

-spec keypairs(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
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
    ),
    ok.

-spec key_exchange(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
key_exchange(_) ->
    lists:foreach(
        fun({Curve, Bytes}) ->
            Alice = binary:copy(<<7>>, Bytes),
            Bob = binary:copy(<<19>>, Bytes),
            AlicePublic = call(Curve, "_derive_public_key", [Alice]),
            BobPublic = call(Curve, "_derive_public_key", [Bob]),
            Shared = call(Curve, "", [BobPublic, Alice]),
            Shared = call(Curve, "", [AlicePublic, Bob]),
            Bytes = byte_size(Shared),
            error = call(Curve, "", [binary:copy(<<0>>, Bytes), Alice])
        end,
        [{x25519, 32}, {x448, 56}]
    ),
    ok.

-spec csprng(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
csprng(_) ->
    Initial = libdecaf_nif:spongerng_csprng_init_from_buffer(<<>>, true),
    Expected = binary:decode_hex(<<"2ED664354AA87699BE93C3B62715A256">>),
    {Next, Expected} = libdecaf_nif:spongerng_csprng_next(Initial, 16),
    {_, Expected} = libdecaf_nif:spongerng_csprng_next(Initial, 16),
    {_, Following} = libdecaf_nif:spongerng_csprng_next(Next, 16),
    true = Following =/= Expected,
    Stirred = libdecaf_nif:spongerng_csprng_stir(Initial, [<<"seed">>]),
    {_, Changed} = libdecaf_nif:spongerng_csprng_next(Stirred, 16),
    true = Changed =/= Expected,
    ok.

-spec prime_order_groups(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
prime_order_groups(Config) ->
    DataDir = filename:join(filename:split(proplists:get_value(data_dir, Config))),
    VectorsFile = filename:join([
        filename:dirname(DataDir),
        "rfc9496_SUITE_data",
        "vectors.config"
    ]),
    {ok, Vectors} = file:consult(VectorsFile),
    lists:foreach(
        fun({Group, Bytes}) ->
            Examples = proplists:get_value(Group, Vectors),
            Points = [hex(Value) || Value <- proplists:get_value(multiples, Examples)],
            [Identity, Base | _] = Points,
            Identity = call(Group, "_identity", []),
            Base = call(Group, "_base", []),
            Table = call(Group, "_precompute", [Base]),
            lists:foreach(
                fun({Index, Point}) ->
                    Scalar = integer(Index, Bytes),
                    true = call(Group, "_point_is_valid", [Point]),
                    Point = call(Group, "_base_scalarmul", [Scalar]),
                    Point = call(Group, "_point_scalarmul", [Base, Scalar]),
                    Point = call(Group, "_precomputed_scalarmul", [Table, Scalar])
                end,
                lists:enumerate(0, Points)
            ),
            lists:foreach(
                fun(Invalid) ->
                    false = call(Group, "_point_is_valid", [hex(Invalid)]),
                    badarg(fun() -> call(Group, "_point_add", [Base, hex(Invalid)]) end)
                end,
                proplists:get_value(invalid, Examples)
            ),
            lists:foreach(
                fun({Input, Output}) ->
                    Expected = hex(Output),
                    Expected = call(Group, "_point_from_hash", [hex(Input)])
                end,
                proplists:get_value(uniform, Examples)
            ),
            group_arithmetic(Group, Bytes, Base, Identity),
            Other =
                case Group of
                    ristretto255 -> decaf448;
                    decaf448 -> ristretto255
                end,
            OtherScalar = call(Other, "_scalar_reduce", [<<1>>]),
            badarg(fun() -> call(Other, "_precomputed_scalarmul", [Table, OtherScalar]) end)
        end,
        [{ristretto255, 32}, {decaf448, 56}]
    ),
    ok.

-spec group_arithmetic(Group, Bytes, Base, Identity) -> Result when
    Group :: ristretto255 | decaf448, Bytes :: pos_integer(), Base :: binary(), Identity :: binary(), Result :: ok.
group_arithmetic(Group, Bytes, Base, Identity) ->
    One = integer(1, Bytes),
    Two = integer(2, Bytes),
    Three = integer(3, Bytes),
    Zero = integer(0, Bytes),
    Double = call(Group, "_point_add", [Base, Base]),
    Double = call(Group, "_point_double", [Base]),
    Base = call(Group, "_point_sub", [Double, Base]),
    true = call(Group, "_point_eq", [Base, Base]),
    false = call(Group, "_point_eq", [Base, Double]),
    Negative = call(Group, "_point_negate", [Base]),
    Identity = call(Group, "_point_add", [Base, Negative]),
    Double = call(Group, "_point_double_scalarmul", [Base, One, Base, One]),
    true = call(Group, "_scalar_is_canonical", [One]),
    One = call(Group, "_scalar_reduce", [<<1>>]),
    Three = call(Group, "_scalar_add", [One, Two]),
    One = call(Group, "_scalar_sub", [Three, Two]),
    Two = call(Group, "_scalar_mul", [One, Two]),
    Negated = call(Group, "_scalar_negate", [One]),
    Zero = call(Group, "_scalar_add", [One, Negated]),
    One = call(Group, "_scalar_halve", [Two]),
    One = call(Group, "_scalar_invert", [One]),
    error = call(Group, "_scalar_invert", [Zero]),
    Nonuniform = call(Group, "_point_from_hash_nonuniform", [One]),
    Uniform = call(Group, "_point_from_hash", [<<One/binary, One/binary>>]),
    Uniform = call(Group, "_point_add", [Nonuniform, Nonuniform]).

-spec upgrade(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
upgrade(_) ->
    Keys = [
        {Curve, call(Curve, "_derive_keypair", [binary:copy(<<7>>, Bytes)])}
     || {Curve, Bytes} <- [{ed25519, 32}, {ed448, 57}]
    ],
    PublicKeys = [{Curve, call(Curve, "_keypair_extract_public_key", [Key])} || {Curve, Key} <- Keys],
    Random = libdecaf_nif:spongerng_csprng_init_from_buffer(<<"seed">>, true),
    {_, Expected} = libdecaf_nif:spongerng_csprng_next(Random, 32),
    Tables = [
        {Group, Bytes, call(Group, "_base", []), call(Group, "_precompute", [call(Group, "_base", [])])}
     || {Group, Bytes} <- [{ristretto255, 32}, {decaf448, 56}]
    ],
    {libdecaf_nif, Beam, Filename} = code:get_object_code(libdecaf_nif),
    {module, libdecaf_nif} = code:load_binary(libdecaf_nif, Filename, Beam),
    PublicKeys = [{Curve, call(Curve, "_keypair_extract_public_key", [Key])} || {Curve, Key} <- Keys],
    {_, Expected} = libdecaf_nif:spongerng_csprng_next(Random, 32),
    lists:foreach(
        fun({Group, Bytes, Base, Table}) ->
            Base = call(Group, "_precomputed_scalarmul", [Table, integer(1, Bytes)]),
            NewTable = call(Group, "_precompute", [Base]),
            Base = call(Group, "_precomputed_scalarmul", [NewTable, integer(1, Bytes)])
        end,
        Tables
    ),
    keypairs([]),
    csprng([]),
    ok.

-spec call(Component, Suffix, Arguments) -> Result when
    Component :: atom(), Suffix :: string(), Arguments :: [term()], Result :: dynamic().
call(Component, Suffix, Arguments) ->
    apply(libdecaf_nif, list_to_atom(atom_to_list(Component) ++ Suffix), Arguments).

-spec hex(Hex) -> Result when Hex :: string() | binary(), Result :: binary().
hex(Value) ->
    binary:decode_hex(iolist_to_binary(Value)).

-spec integer(Integer, Bytes) -> Result when Integer :: non_neg_integer(), Bytes :: pos_integer(), Result :: binary().
integer(Value, Bytes) ->
    <<Value:(Bytes * 8)/unsigned-little-integer>>.

-spec badarg(Function) -> Result when Function :: fun(() -> term()), Result :: ok.
badarg(Fun) ->
    try Fun() of
        Value -> error({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.
