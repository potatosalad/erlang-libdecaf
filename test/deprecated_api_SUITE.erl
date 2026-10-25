%%% % @format
-module(deprecated_api_SUITE).
-compile(warn_missing_spec_all).
-moduledoc """
Historical libdecaf exports, raw streaming states, and deprecated API contracts.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    init_per_suite/1,
    curves/1,
    exports_and_deprecation/1,
    fixed_hashes/1,
    invalid_arguments/1,
    shake/1,
    spongerng/1,
    utilities/1
]).

-type fixed_hash_algorithm() ::
    sha2_512 | sha3_224 | sha3_256 | sha3_384 | sha3_512 | keccak_224 | keccak_256 | keccak_384 | keccak_512.

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [exports_and_deprecation, fixed_hashes, shake, curves, spongerng, invalid_arguments, utilities].

-spec init_per_suite(Config) -> Config when Config :: ct_suite:ct_config().
init_per_suite(Config) ->
    {module, libdecaf} = code:ensure_loaded(libdecaf),
    Config.

-spec exports_and_deprecation(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
exports_and_deprecation(Config) ->
    % Snapshot of the upstream main/src/libdecaf.erl public and internal exports.
    {ok, [Expected]} = file:consult(filename:join(proplists:get_value(data_dir, Config), "exports.config")),
    99 = length(Expected),
    {ok, {docs_v1, _, erlang, _, _, _, Entries}} = code:get_doc(libdecaf),
    Deprecated = lists:flatten(proplists:get_value(deprecated, libdecaf:module_info(attributes))),
    lists:foreach(
        fun({Name, Arity}) ->
            true = erlang:function_exported(libdecaf, Name, Arity),
            {Name, Arity, Replacement} = lists:keyfind(Name, 1, [D || D = {_, A, _} <- Deprecated, A =:= Arity]),
            true = length(Replacement) > 0,
            {{function, Name, Arity}, _, _, Doc, Metadata} = lists:keyfind({function, Name, Arity}, 1, Entries),
            <<"Deprecated API">> = maps:get(group, Metadata),
            true = maps:is_key(deprecated, Metadata),
            true = is_binary(maps:get(<<"en">>, Doc))
        end,
        Expected -- [{start, 0}]
    ),
    lists:foreach(
        fun({Name, Arity}) ->
            true = erlang:function_exported(libdecaf, Name, Arity),
            false = lists:member({Name, Arity}, [{N, A} || {N, A, _} <- Deprecated]),
            {{function, Name, Arity}, _, _, _, Metadata} = lists:keyfind({function, Name, Arity}, 1, Entries),
            false = maps:is_key(deprecated, Metadata)
        end,
        [
            {start, 0},
            {hash, 2},
            {hash_init, 1},
            {hash_update, 2},
            {hash_final, 1},
            {xof, 3},
            {xof_init, 1},
            {xof_absorb, 2},
            {xof_squeeze, 2}
        ]
    ),
    ok.

-spec fixed_hashes(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
fixed_hashes(_) ->
    % These call patterns include silicon's one-shot and mcrypto's generated API.
    lists:foreach(
        fun({Algorithm, Size}) ->
            lists:foreach(
                fun(Message) ->
                    Digest = libdecaf:hash(Algorithm, Message),
                    Size = byte_size(Digest),
                    Digest = call(Algorithm, "", [[Message]]),
                    Initial = call(Algorithm, "_init", []),
                    true = is_reference(Initial),
                    First = call(Algorithm, "_update", [Initial, <<"a">>]),
                    Branch = call(Algorithm, "_update", [First, <<"bc">>]),
                    ABC = libdecaf:hash(Algorithm, <<"abc">>),
                    ABC = call(Algorithm, "_final", [Branch]),
                    Updated = call(Algorithm, "_update", [Initial, [Message]]),
                    true = is_reference(Updated),
                    Digest = call(Algorithm, "_final", [Updated]),
                    Digest = call(Algorithm, "_final", [Updated]),
                    Empty = libdecaf:hash(Algorithm, <<>>),
                    Empty = call(Algorithm, "_final", [Initial]),
                    lists:foreach(
                        fun(Length) ->
                            Prefix = binary:part(Digest, 0, Length),
                            Prefix = call(Algorithm, "", [Message, Length]),
                            Prefix = call(Algorithm, "_final", [Updated, Length])
                        end,
                        [0, 1, Size - 1, Size]
                    ),
                    badarg(fun() -> call(Algorithm, "", [Message, Size + 1]) end),
                    badarg(fun() -> call(Algorithm, "_final", [Updated, Size + 1]) end)
                end,
                [<<>>, <<"abc">>, binary:copy(<<42>>, 65537)]
            )
        end,
        hashes()
    ),
    ok.

-spec shake(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
shake(_) ->
    lists:foreach(
        fun(Algorithm) ->
            Initial = call(Algorithm, "_init", []),
            true = is_reference(Initial),
            Updated = call(Algorithm, "_update", [call(Algorithm, "_update", [Initial, <<"a">>]), [<<"bc">>]]),
            lists:foreach(
                fun(Length) ->
                    Expected = libdecaf:xof(Algorithm, <<"abc">>, Length),
                    Expected = call(Algorithm, "", [[<<"abc">>], Length]),
                    Expected = call(Algorithm, "_final", [Updated, Length]),
                    Expected = call(Algorithm, "_final", [Updated, Length]),
                    true = is_binary(Expected),
                    Empty = libdecaf:xof(Algorithm, <<>>, Length),
                    Empty = call(Algorithm, "_final", [Initial, Length])
                end,
                [0, 1, 32, 65537]
            )
        end,
        [shake128, shake256]
    ),
    ok.

-spec curves(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
curves(_) ->
    lists:foreach(
        fun({Curve, Bytes, Context, XCurve}) ->
            Secret = binary:copy(<<7>>, Bytes),
            Keypair = call(Curve, "_derive_keypair", [Secret]),
            true = is_reference(Keypair),
            Secret = call(Curve, "_keypair_extract_private_key", [Keypair]),
            Public = call(Curve, "_keypair_extract_public_key", [Keypair]),
            Public = call(Curve, "_derive_public_key", [Secret]),
            Signature = call(Curve, "_keypair_sign", [Keypair, <<"message">>, 0, Context]),
            Signature = call(Curve, "_sign", [Secret, Public, <<"message">>, 0, Context]),
            true = call(Curve, "_verify", [Signature, Public, <<"message">>, 0, Context]),
            false = call(Curve, "_verify", [Signature, Public, <<"changed">>, 0, Context]),
            Prehashed = call(Curve, "_keypair_sign_prehash", [Keypair, <<"message">>, <<>>]),
            Prehashed = call(Curve, "_sign_prehash", [Secret, Public, <<"message">>, <<>>]),
            true = call(Curve, "_verify_prehash", [Prehashed, Public, <<"message">>, <<>>]),
            Prehash =
                case Curve of
                    ed25519 -> libdecaf:hash(sha2_512, <<"message">>);
                    ed448 -> libdecaf:xof(shake256, <<"message">>, 64)
                end,
            Prehashed = call(Curve, "_sign", [Secret, Public, Prehash, 1, <<>>]),
            true = call(Curve, "_verify", [Prehashed, Public, Prehash, 1, <<>>]),
            OtherPublic = call(Curve, "_derive_public_key", [binary:copy(<<19>>, Bytes)]),
            rejected_keypair(fun() -> call(Curve, "_sign", [Secret, OtherPublic, <<"message">>, 0, Context]) end),
            rejected_keypair(fun() -> call(Curve, "_sign_prehash", [Secret, OtherPublic, <<"message">>, <<>>]) end),
            Scalar = call(Curve, "_convert_private_key_to_" ++ atom_to_list(XCurve), [Secret]),
            XPublic = call(XCurve, "_derive_public_key", [Scalar]),
            XPublic = call(Curve, "_convert_public_key_to_" ++ atom_to_list(XCurve), [Public]),
            XPublic = call(XCurve, "_generate_key", [Scalar]),
            OtherScalar = binary:copy(<<19>>, byte_size(Scalar)),
            OtherXPublic = call(XCurve, "_derive_public_key", [OtherScalar]),
            Shared = call(XCurve, "", [OtherXPublic, Scalar]),
            Shared = call(XCurve, "", [XPublic, OtherScalar]),
            error = call(XCurve, "", [binary:copy(<<0>>, byte_size(Scalar)), Scalar])
        end,
        [{ed25519, 32, no_context, x25519}, {ed448, 57, <<>>, x448}]
    ),
    ok.

-spec spongerng(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
spongerng(Config) ->
    Initial = call(spongerng, "_init_from_buffer", [<<>>, true]),
    true = is_reference(Initial),
    Expected = binary:decode_hex(<<"2ED664354AA87699BE93C3B62715A256">>),
    {Next, Expected} = call(spongerng, "_next", [Initial, 16]),
    true = is_reference(Next),
    {_, Expected} = call(spongerng, "_next", [Initial, 16]),
    {_, Following} = call(spongerng, "_next", [Next, 16]),
    true = Following =/= Expected,
    Stirred = call(spongerng, "_stir", [Initial, [<<"seed">>]]),
    {_, Changed} = call(spongerng, "_next", [Stirred, 16]),
    true = Changed =/= Expected,
    DataDir = filename:join(filename:split(proplists:get_value(data_dir, Config))),
    File = filename:join([filename:dirname(DataDir), "spongerng_SUITE_data", "seed.txt"]),
    FileState = call(spongerng, "_init_from_file", [File, 1406, true]),
    FileExpected = binary:decode_hex(<<"70636E1D0C39837C9B0DF10EC4220CB7">>),
    {_, FileExpected} = call(spongerng, "_next", [FileState, 16]),
    Random = call(spongerng, "_init_from_dev_urandom", []),
    {_, RandomOutput} = call(spongerng, "_next", [Random, 16]),
    16 = byte_size(RandomOutput),
    ok.

-spec invalid_arguments(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
invalid_arguments(_) ->
    lists:foreach(
        fun({Algorithm, _}) ->
            State = call(Algorithm, "_init", []),
            badarg(fun() -> call(Algorithm, "_update", [State, [invalid_iodata]]) end),
            badarg(fun() -> call(Algorithm, "_update", [make_ref(), <<>>]) end),
            badarg(fun() -> call(Algorithm, "_final", [make_ref()]) end),
            badarg(fun() -> call(Algorithm, "_final", [State, -1]) end)
        end,
        hashes()
    ),
    Hash = call(sha3_256, "_init", []),
    XOF = call(shake128, "_init", []),
    badarg(fun() -> call(sha3_256, "_update", [XOF, <<>>]) end),
    badarg(fun() -> call(shake128, "_update", [Hash, <<>>]) end),
    badarg(fun() -> call(sha3_256, "_final", [XOF]) end),
    badarg(fun() -> call(shake128, "_final", [Hash, 32]) end),
    badarg(fun() -> call(shake128, "_final", [XOF, -1]) end),
    ok.

-spec utilities(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
utilities(_) ->
    {ok, _} = libdecaf:start(),
    Directory = call(priv_dir, "", []),
    Expected =
        case code:priv_dir(libdecaf) of
            {error, bad_name} ->
                ModulePath = code:which(libdecaf),
                true = is_list(ModulePath),
                filename:join([filename:dirname(ModulePath), "../priv"]);
            PrivDir ->
                PrivDir
        end,
    {ok, Info} = file:read_file_info(Expected),
    {ok, Info} = file:read_file_info(Directory),
    true = filelib:is_dir(Directory),
    ok.

-spec hashes() -> Result when Result :: [{fixed_hash_algorithm(), pos_integer()}].
hashes() ->
    [
        {sha2_512, 64},
        {sha3_224, 28},
        {sha3_256, 32},
        {sha3_384, 48},
        {sha3_512, 64},
        {keccak_224, 28},
        {keccak_256, 32},
        {keccak_384, 48},
        {keccak_512, 64}
    ].

-spec call(Name, Suffix, Arguments) -> Result when
    Name :: atom(), Suffix :: string(), Arguments :: [term()], Result :: dynamic().
call(Name, Suffix, Arguments) ->
    apply(libdecaf, list_to_atom(atom_to_list(Name) ++ Suffix), Arguments).

-spec badarg(Function) -> Result when Function :: fun(() -> term()), Result :: ok.
badarg(Function) ->
    try Function() of
        Value -> ct:fail({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

-spec rejected_keypair(Function) -> Result when Function :: fun(() -> term()), Result :: ok.
rejected_keypair(Function) ->
    try Function() of
        Value -> ct:fail({mismatched_keypair_accepted, Value})
    catch
        error:{error, _, _} -> ok
    end.
