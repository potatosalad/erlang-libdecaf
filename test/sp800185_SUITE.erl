%%% % @format
-module(sp800185_SUITE).
-compile(warn_missing_spec_all).
-moduledoc """
Published SP 800-185 vectors, RFC 9861 HopMAC composition, and native API lifecycles.
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-include_lib("common_test/include/ct.hrl").
-export([
    all/0,
    kmac_draft_vectors/1,
    nist_vectors/1,
    reference_framing/1,
    tuple_boundaries/1,
    parallel_boundaries/1,
    length_binding/1,
    hopmac_reference/1,
    lifecycle/1,
    invalid_arguments/1,
    trapping/1,
    cancellation/1,
    upgrade/1,
    documentation/1
]).

-type family() :: cshake | hopmac | keccak | kmac | kt | parallelhash | sha3 | tuplehash | turboshake.

-type draft_vector() :: {atom(), kmac128 | kmac256, atom(), binary(), binary(), binary(), binary()}.
-type kmac_vector() :: {atom(), kmac128 | kmac256, nist, binary(), binary(), binary(), binary()}.
-type tuple_vector() :: {atom(), tuplehash128 | tuplehash256, boolean(), [binary()], binary(), binary()}.
-type parallel_vector() :: {
    atom(), parallelhash128 | parallelhash256, boolean(), pos_integer(), binary(), binary(), binary()
}.

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [
        kmac_draft_vectors,
        nist_vectors,
        reference_framing,
        tuple_boundaries,
        parallel_boundaries,
        length_binding,
        hopmac_reference,
        lifecycle,
        invalid_arguments,
        trapping,
        cancellation,
        upgrade,
        documentation
    ].

-spec kmac_draft_vectors(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
kmac_draft_vectors(Config) ->
    Vectors = vectors(draft, Config),
    18 = length(Vectors),
    lists:foreach(
        fun({_Name, Type, Kind, KeyHex, DataHex, CustomHex, TagHex}) ->
            Key = binary:decode_hex(KeyHex),
            Input = binary:decode_hex(DataHex),
            Data =
                case Kind of
                    kdf -> <<Input/binary, 1>>;
                    _ -> Input
                end,
            check(kmac, Type, Data, [Key, binary:decode_hex(CustomHex)], binary:decode_hex(TagHex), false)
        end,
        Vectors
    ),
    ok.

-spec nist_vectors(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
nist_vectors(Config) ->
    lists:foreach(
        fun({Kind, Xof}) ->
            Records = vectors(Kind, Config),
            6 = length(Records),
            lists:foreach(
                fun({_Name, Type, nist, Key, Data, Custom, Output}) ->
                    check(
                        kmac,
                        selector(Type, Xof),
                        binary:decode_hex(Data),
                        [binary:decode_hex(Key), binary:decode_hex(Custom)],
                        binary:decode_hex(Output),
                        Xof
                    )
                end,
                Records
            )
        end,
        [{nist, false}, {kmac_xof, true}]
    ),
    lists:foreach(
        fun
            (tuplehash) ->
                Records = vectors(tuplehash, Config),
                12 = length(Records),
                lists:foreach(
                    fun({_Name, Type, Xof, Elements, Custom, Output}) ->
                        check(
                            tuplehash,
                            selector(Type, Xof),
                            [binary:decode_hex(E) || E <- Elements],
                            [binary:decode_hex(Custom)],
                            binary:decode_hex(Output),
                            Xof
                        )
                    end,
                    Records
                );
            (parallelhash) ->
                Records = vectors(parallelhash, Config),
                12 = length(Records),
                lists:foreach(
                    fun({_Name, Type, Xof, Size, Data, Custom, Output}) ->
                        check(
                            parallelhash,
                            selector(Type, Xof),
                            binary:decode_hex(Data),
                            [Size, binary:decode_hex(Custom)],
                            binary:decode_hex(Output),
                            Xof
                        )
                    end,
                    Records
                )
        end,
        [tuplehash, parallelhash]
    ),
    ok.

-spec selector(Type, Xof) -> Result when Type :: atom(), Xof :: boolean(), Result :: atom().
selector(Type, false) -> Type;
selector(Type, true) -> list_to_atom(re:replace(atom_to_list(Type), "(128|256)$", "xof\\1", [{return, list}])).

-spec check(Family, Type, Input, Parameters, Expected, Xof) -> Result when
    Family :: family(),
    Type :: atom(),
    Input :: iodata(),
    Parameters :: [binary() | pos_integer()],
    Expected :: binary(),
    Xof :: boolean(),
    Result :: ok.
check(Family, Type, Input, Parameters, Expected, Xof) ->
    Mode =
        case Xof of
            true -> "xof";
            false -> "hash"
        end,
    Once = list_to_atom(Mode),
    Update =
        case Xof of
            true -> xof_absorb;
            false -> hash_update
        end,
    Length = byte_size(Expected),
    InitArgs =
        [Type] ++
            case Xof of
                true -> Parameters;
                false -> [Length | Parameters]
            end,
    case Family of
        F when F == parallelhash; F == hopmac ->
            Expected =
                case Xof of
                    true -> libdecaf:parallel_xof(parallel_xof_parameters(Type, Parameters), Input, Length);
                    false -> libdecaf:parallel_hash(parallel_hash_parameters(Type, Length, Parameters), Input)
                end;
        _ ->
            ok
    end,
    lists:foreach(
        fun(Module) ->
            Expected =
                case Xof of
                    true -> Module:xof(list_to_tuple([Type | Parameters]), Input, Length);
                    false -> apply(Module, Once, [list_to_tuple([Type, Length | Parameters]), Input])
                end,
            Expected = apply(libdecaf_nif, Type, [Input, Length | Parameters]),
            Initial = apply(libdecaf_nif, list_to_atom(atom_to_list(Type) ++ "_" ++ Mode ++ "_init"), tl(InitArgs)),
            true = is_reference(Initial),
            GenericInit =
                case Xof of
                    true -> xof_init;
                    false -> hash_init
                end,
            Generic = apply(Module, GenericInit, [list_to_tuple(InitArgs)]),
            Chunks =
                case Family of
                    tuplehash ->
                        true = is_list(Input),
                        Input;
                    _ ->
                        chunks(iolist_to_binary(Input), 137)
                end,
            State = lists:foldl(fun(Chunk, Acc) -> Module:Update(Acc, [Chunk]) end, Initial, Chunks),
            State2 = lists:foldl(fun(Chunk, Acc) -> Module:Update(Acc, Chunk) end, Generic, Chunks),
            case Xof of
                false ->
                    Expected = Module:hash_final(State),
                    Expected = Module:hash_final(State),
                    Expected = Module:hash_final(State2);
                true ->
                    {Z, <<>>} = Module:xof_squeeze(State, 0),
                    badarg(fun() -> Module:xof_absorb(Z, <<>>) end),
                    {Next, First} = Module:xof_squeeze(Z, Length div 2),
                    {_, Last} = Module:xof_squeeze(Next, Length - byte_size(First)),
                    Expected = <<First/binary, Last/binary>>,
                    {_, Expected} = Module:xof_squeeze(State, Length),
                    {_, Expected} = Module:xof_squeeze(State2, Length)
            end
        end,
        [libdecaf, libdecaf_nif]
    ).

-spec reference_framing(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
reference_framing(_) ->
    lists:foreach(
        fun({Kmac, Tuple, Parallel, Cshake, Shake, Rate}) ->
            lists:foreach(
                fun(Size) ->
                    Key = binary:copy(<<42>>, Size),
                    Custom = binary:copy(<<17>>, Size),
                    Data = binary:copy(<<123>>, Size),
                    EncodedKey = bytepad(encode_string(Key), Rate),
                    Elements = [<<>>, Data, <<"tail">>],
                    EncodedElements = [encode_string(E) || E <- Elements],
                    lists:foreach(
                        fun(Xof) ->
                            Length = 32,
                            Bits =
                                case Xof of
                                    true -> 0;
                                    false -> Length * 8
                                end,
                            Expected = libdecaf:xof(
                                {Cshake, <<"KMAC">>, Custom},
                                [
                                    EncodedKey, Data, right_encode(Bits)
                                ],
                                Length
                            ),
                            check(kmac, selector(Kmac, Xof), Data, [Key, Custom], Expected, Xof),
                            TupleExpected = libdecaf:xof(
                                {Cshake, <<"TupleHash">>, Custom},
                                [
                                    EncodedElements, right_encode(Bits)
                                ],
                                Length
                            ),
                            check(tuplehash, selector(Tuple, Xof), Elements, [Custom], TupleExpected, Xof),
                            B = 8,
                            Leaves = chunks_nonempty(Data, B),
                            CVs = [libdecaf:xof(Shake, Leaf, 200 - Rate) || Leaf <- Leaves],
                            ParallelExpected = libdecaf:xof(
                                {Cshake, <<"ParallelHash">>, Custom},
                                [
                                    left_encode(B), CVs, right_encode(length(Leaves)), right_encode(Bits)
                                ],
                                Length
                            ),
                            check(parallelhash, selector(Parallel, Xof), Data, [B, Custom], ParallelExpected, Xof)
                        end,
                        [false, true]
                    )
                end,
                [0, 1, Rate - 4, Rate - 1, Rate, Rate + 1, 65537]
            )
        end,
        [
            {kmac128, tuplehash128, parallelhash128, cshake128, shake128, 168},
            {kmac256, tuplehash256, parallelhash256, cshake256, shake256, 136}
        ]
    ),
    ok.

-spec tuple_boundaries(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
tuple_boundaries(_) ->
    lists:foreach(
        fun({Hash, Xof}) ->
            A = libdecaf:hash({Hash, 32}, [<<"a">>, <<"bc">>]),
            B = libdecaf:hash({Hash, 32}, [<<"ab">>, <<"c">>]),
            true = A =/= B,
            true = libdecaf:hash({Hash, 32}, []) =/= libdecaf:hash({Hash, 32}, [<<>>]),
            true = libdecaf:xof(Xof, [], 32) =/= libdecaf:xof(Xof, [<<>>], 32),
            State = libdecaf:hash_init({Hash, 32}),
            A = libdecaf:hash_final(libdecaf:hash_update(libdecaf:hash_update(State, <<"a">>), <<"bc">>)),
            false = libdecaf:hash_final(State) =:= A
        end,
        [{tuplehash128, tuplehashxof128}, {tuplehash256, tuplehashxof256}]
    ),
    ok.

-spec parallel_boundaries(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
parallel_boundaries(_) ->
    lists:foreach(
        fun(Type) ->
            lists:foreach(
                fun(B) ->
                    lists:foreach(
                        fun(Size) ->
                            Input = binary:copy(<<42>>, Size),
                            Expected = libdecaf:hash({Type, 32, B, <<"blocks">>}, Input),
                            check(parallelhash, Type, Input, [B, <<"blocks">>], Expected, false)
                        end,
                        lists:usort([0, 1, B - 1, B, B + 1, 2 * B, 2 * B + 1])
                    )
                end,
                [1, 2, 7, 8, 12, 136, 168, 257, 65537]
            ),
            true =
                libdecaf:hash({Type, 32, 8}, <<"abcdefghijk">>) =/=
                    libdecaf:hash({Type, 32, 9}, <<"abcdefghijk">>)
        end,
        [parallelhash128, parallelhash256]
    ),
    ok.

-spec length_binding(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
length_binding(_) ->
    lists:foreach(
        fun({_Family, Type, Input, Parameters}) ->
            Name = hash,
            Short = apply(libdecaf, Name, [list_to_tuple([Type, 16 | Parameters]), Input]),
            Long = apply(libdecaf, Name, [list_to_tuple([Type, 32 | Parameters]), Input]),
            true = Short =/= binary:part(Long, 0, 16),
            XofParameters = xof_parameters(selector(Type, true), Parameters),
            XofShort = libdecaf:xof(XofParameters, Input, 16),
            XofLong = libdecaf:xof(XofParameters, Input, 32),
            XofShort = binary:part(XofLong, 0, 16),
            true = Short =/= XofShort
        end,
        [
            {kmac, kmac128, <<>>, [<<>>]},
            {kmac, kmac256, <<>>, [<<>>]},
            {tuplehash, tuplehash128, [<<"abc">>], []},
            {tuplehash, tuplehash256, [], []},
            {parallelhash, parallelhash128, <<"abc">>, [8]},
            {parallelhash, parallelhash256, <<>>, [8]}
        ]
    ),
    <<"E6AFF27FEF95903EB939BC3745730D34">> = binary:encode_hex(libdecaf:hash({kmac128, 16, <<>>}, <<>>)),
    ok.

-spec hopmac_reference(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
hopmac_reference(_) ->
    %% RFC 9861 section 4: KT(Key, KT(Message, Customization, 32/64), Length).
    lists:foreach(
        fun({Type, KT, InnerLength}) ->
            lists:foreach(
                fun(Size) ->
                    Key = binary:copy(<<42>>, Size),
                    Message = binary:copy(<<19>>, Size),
                    Custom = binary:copy(<<17>>, Size),
                    Digest = libdecaf:xof({KT, Custom}, Message, InnerLength),
                    Expected = libdecaf:xof({KT, Digest}, Key, 169),
                    check(hopmac, Type, Message, [Key, Custom], Expected, false),
                    check(hopmac, Type, Message, [Key, Custom], Expected, true)
                end,
                [0, 1, 32, 69, 8191, 8192, 8193, 65537]
            )
        end,
        [{hopmac128, kt128, 32}, {hopmac256, kt256, 64}]
    ),
    ok.

-spec lifecycle(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
lifecycle(_) ->
    lists:foreach(
        fun({Family, Hash, Xof, Parameters}) ->
            lists:foreach(
                fun(Mode) ->
                    Type =
                        case Mode of
                            false -> Hash;
                            true -> Xof
                        end,
                    Input =
                        case Family of
                            tuplehash -> [<<"message">>];
                            _ -> <<"message">>
                        end,
                    Expected =
                        case Mode of
                            true -> libdecaf:xof(xof_parameters(Type, Parameters), Input, 32);
                            false -> libdecaf:hash(hash_parameters(Type, 32, Parameters), Input)
                        end,
                    check(Family, Type, Input, Parameters, Expected, Mode)
                end,
                [false, true]
            )
        end,
        families()
    ),
    ok.

-spec families() -> Result when Result :: [{family(), atom(), atom(), [binary() | pos_integer()]}].
families() ->
    [
        {cshake, cshake128, cshake128, []},
        {cshake, cshake256, cshake256, [<<>>, <<"custom">>]},
        {hopmac, hopmac128, hopmac128, [<<"key">>]},
        {hopmac, hopmac256, hopmac256, [<<"key">>, <<"custom">>]},
        {keccak, keccakxof_128, keccakxof_128, []},
        {keccak, keccakxof_256, keccakxof_256, []},
        {kmac, kmac128, kmacxof128, [<<"key">>]},
        {kmac, kmac256, kmacxof256, [<<"key">>, <<"custom">>]},
        {kt, kt128, kt128, []},
        {kt, kt256, kt256, [<<"custom">>]},
        {parallelhash, parallelhash128, parallelhashxof128, [8]},
        {parallelhash, parallelhash256, parallelhashxof256, [12, <<"custom">>]},
        {sha3, shake128, shake128, []},
        {sha3, shake256, shake256, []},
        {tuplehash, tuplehash128, tuplehashxof128, []},
        {tuplehash, tuplehash256, tuplehashxof256, [<<"custom">>]},
        {turboshake, turboshake128, turboshake128, []},
        {turboshake, turboshake256, turboshake256, [127]}
    ].

-spec invalid_arguments(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
invalid_arguments(_) ->
    lists:foreach(
        fun(Module) ->
            Hash = Module:hash_init(sha3_256),
            Xof = Module:xof_init(shake128),
            lists:foreach(fun badarg/1, [
                fun() -> Module:hash_init({cshake128, -1}) end,
                fun() -> Module:hash_init({kmacxof128, 32, <<>>}) end,
                fun() -> Module:xof_init({kmac128, <<>>}) end,
                fun() -> Module:hash_init({parallelhash128, 32, 0}) end,
                fun() -> Module:xof_init({parallelhashxof128, -1}) end,
                fun() -> Module:hash_init({turboshake128, 32, <<31>>}) end,
                fun() -> Module:xof_init({turboshake128, 0}) end,
                fun() -> Module:hash_init({kt128, 32, invalid}) end,
                fun() -> Module:xof_init({hopmac128, invalid}) end,
                fun() -> Module:hash_init({kmac128, 1 bsl 61, <<>>}) end,
                fun() -> Module:hash_init(shake128) end,
                fun() -> Module:hash_init({sha3_224, 29}) end,
                fun() -> Module:hash_init({cshake128}) end,
                fun() -> Module:xof_init({shake128, 32}) end,
                fun() -> Module:hash_init({}) end,
                fun() -> Module:hash_init({sha3_256, 32, <<>>}) end,
                fun() -> Module:hash_update(Xof, <<>>) end,
                fun() -> Module:hash_final(Xof) end,
                fun() -> Module:xof_absorb(Hash, <<>>) end,
                fun() -> Module:xof_squeeze(Hash, 32) end,
                fun() -> Module:xof_squeeze(Xof, -1) end,
                fun() -> Module:hash_update(Hash, [256]) end,
                fun() ->
                    apply(Module, hash, [{tuplehash128, 32}, libdecaf_ct:call(erlang, '++', [[<<>>], invalid])])
                end,
                fun() -> Module:xof(tuplehashxof128, <<"flattened">>, 32) end,
                fun() -> Module:xof_absorb(make_ref(), <<>>) end
            ])
        end,
        [libdecaf, libdecaf_nif]
    ),
    ok.

-spec trapping(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
trapping(_) ->
    Large = binary:copy(<<42>>, 200001),
    lists:foreach(
        fun({Family, Hash, Xof, Parameters}) ->
            Name = hash,
            Data =
                case Family of
                    tuplehash -> [Large, <<>>];
                    _ -> Large
                end,
            _ = traced(fun() -> apply(libdecaf, Name, [list_to_tuple([Hash, 65537 | Parameters]), Data]) end, [
                libdecaf_nif_hash_absorb_continue, libdecaf_nif_hash_final_continue
            ]),
            Init = xof_init,
            State0 = apply(libdecaf, Init, [list_to_tuple([Xof | Parameters])]),
            State1 = traced(fun() -> libdecaf:xof_absorb(State0, Large) end, [libdecaf_nif_xof_absorb_continue]),
            {_Next, Output} = traced(fun() -> libdecaf:xof_squeeze(State1, 65537) end, [
                libdecaf_nif_xof_squeeze_continue
            ]),
            65537 = byte_size(Output)
        end,
        families()
    ),
    Empty = lists:duplicate(100001, <<>>),
    _ = traced(fun() -> libdecaf:hash({tuplehash128, 32}, Empty) end, [libdecaf_nif_hash_absorb_continue]),
    _ = traced(fun() -> libdecaf:hash({parallelhash128, 32, 1}, Large) end, [
        libdecaf_nif_hash_absorb_continue
    ]),
    ok.

-spec cancellation(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
cancellation(_) ->
    Large = binary:copy(<<42>>, 1000001),
    lists:foreach(
        fun({_Family, _Hash, Xof, Parameters}) ->
            Init = xof_init,
            State = apply(libdecaf, Init, [list_to_tuple([Xof | Parameters])]),
            P = "libdecaf_nif_xof",
            cancelled(fun() -> libdecaf:xof_absorb(State, Large) end, list_to_atom(P ++ "_absorb_continue")),
            cancelled(fun() -> libdecaf:xof_squeeze(State, 8000001) end, list_to_atom(P ++ "_squeeze_continue"))
        end,
        families()
    ),
    cancelled(
        fun() -> libdecaf:xof_init({hopmac128, Large, Large}) end,
        libdecaf_nif_xof_absorb_continue
    ),
    cancelled(
        fun() -> libdecaf:hash_init({kmac128, 32, Large, Large}) end,
        libdecaf_nif_hash_absorb_continue
    ),
    KT = libdecaf:xof_init({kt128, Large}),
    cancelled(fun() -> libdecaf:xof_squeeze(KT, 32) end, libdecaf_nif_xof_absorb_continue),
    erlang:garbage_collect(),
    ok.

-spec upgrade(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
upgrade(_) ->
    States = [
        begin
            HashInit = hash_init,
            XofInit = xof_init,
            Hash = libdecaf:hash_update(apply(libdecaf, HashInit, [list_to_tuple([H, 32 | Parameters])]), <<"abc">>),
            Xof = libdecaf:xof_absorb(apply(libdecaf, XofInit, [list_to_tuple([X | Parameters])]), <<"abc">>),
            {Advanced, First} = libdecaf:xof_squeeze(Xof, 16),
            {_, Last} = libdecaf:xof_squeeze(Advanced, 16),
            {Hash, libdecaf:hash_final(Hash), Xof, Advanced, First, Last}
        end
     || {_Family, H, X, Parameters} <- families()
    ],
    {Module, Binary, Filename} = code:get_object_code(libdecaf_nif),
    {module, Module} = code:load_binary(Module, Filename, Binary),
    lists:foreach(
        fun({Hash, Digest, Xof, Advanced, First, Last}) ->
            Digest = libdecaf:hash_final(Hash),
            {_, First} = libdecaf:xof_squeeze(Xof, 16),
            {_, Last} = libdecaf:xof_squeeze(Advanced, 16),
            libdecaf_ct:assert_badarg(libdecaf, xof_absorb, [Advanced, <<>>])
        end,
        States
    ),
    true = code:soft_purge(libdecaf_nif),
    ok.

-spec vectors
    (Kind, Config) -> Records when
        Kind :: draft, Config :: ct_suite:ct_config(), Records :: [draft_vector()];
    (Kind, Config) -> Records when
        Kind :: nist | kmac_xof, Config :: ct_suite:ct_config(), Records :: [kmac_vector()];
    (Kind, Config) -> Records when
        Kind :: tuplehash, Config :: ct_suite:ct_config(), Records :: [tuple_vector()];
    (Kind, Config) -> Records when
        Kind :: parallelhash, Config :: ct_suite:ct_config(), Records :: [parallel_vector()].
vectors(Kind, Config) ->
    File = atom_to_list(Kind) ++ ".config",
    {ok, Records} = file:consult(filename:join(?config(data_dir, Config), File)),
    Records.

-spec encode_string(Input) -> Result when Input :: binary(), Result :: iodata().
encode_string(Binary) -> [left_encode(byte_size(Binary) * 8), Binary].
-spec chunks(Input, Size) -> Result when Input :: binary(), Size :: pos_integer(), Result :: [binary()].
chunks(<<>>, _) -> [<<>>];
chunks(Input, Size) -> chunks_nonempty(Input, Size).
-spec chunks_nonempty(Input, Size) -> Result when Input :: binary(), Size :: pos_integer(), Result :: [binary()].
chunks_nonempty(<<>>, _) ->
    [];
chunks_nonempty(Input, Size) when byte_size(Input) =< Size -> [Input];
chunks_nonempty(Input, Size) ->
    <<Head:Size/binary, Tail/binary>> = Input,
    [Head | chunks_nonempty(Tail, Size)].

-spec documentation(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
documentation(_) ->
    {ok, {docs_v1, _, erlang, <<"text/markdown">>, _, _, Entries}} = code:get_doc(libdecaf),
    lists:foreach(
        fun
            ({{function, _, _}, _, _, #{<<"en">> := Doc}, _}) ->
                case re:run(Doc, <<"```erlang\\n(.*?)```">>, [global, dotall, {capture, [1], binary}]) of
                    {match, Examples} ->
                        lists:foreach(
                            fun([Example]) ->
                                {ok, Tokens, _} = erl_scan:string(libdecaf_ct:unicode_list(Example)),
                                {ok, Expressions} = erl_parse:parse_exprs(Tokens),
                                {value, _, _} = erl_eval:exprs(Expressions, erl_eval:new_bindings())
                            end,
                            Examples
                        );
                    nomatch ->
                        ok
                end;
            (_) ->
                ok
        end,
        Entries
    ),
    ok.

-spec left_encode(Integer) -> Result when Integer :: non_neg_integer(), Result :: binary().
left_encode(Integer) ->
    Bytes = binary:encode_unsigned(Integer),
    <<(byte_size(Bytes)), Bytes/binary>>.

-spec right_encode(Integer) -> Result when Integer :: non_neg_integer(), Result :: binary().
right_encode(Integer) ->
    Bytes = binary:encode_unsigned(Integer),
    <<Bytes/binary, (byte_size(Bytes))>>.

-spec bytepad(Input, Width) -> Result when Input :: iodata(), Width :: pos_integer(), Result :: binary().
bytepad(Input, Width) ->
    Binary = iolist_to_binary([left_encode(Width), Input]),
    Padding = (Width - byte_size(Binary) rem Width) rem Width,
    <<Binary/binary, 0:(Padding * 8)>>.

-spec badarg(Function) -> Result when Function :: fun(() -> term()), Result :: ok.
badarg(Fun) ->
    try Fun() of
        Value -> ct:fail({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

-spec traced(Function, Expected) -> Result when Function :: fun(() -> Value), Expected :: [atom()], Result :: Value.
traced(Fun, Expected) ->
    with_trace(Fun, fun(Pid, Ref) -> trace_result(Pid, Ref, Expected) end).

-spec trace_result(Pid, Monitor, Expected) -> Result when
    Pid :: pid(), Monitor :: reference(), Expected :: [atom()], Result :: dynamic().
trace_result(Pid, Ref, Expected) ->
    receive
        {trace, Pid, out, {libdecaf_nif, Function, 1}} ->
            trace_result(Pid, Ref, lists:delete(Function, Expected));
        {trace, Pid, _, _} ->
            trace_result(Pid, Ref, Expected);
        {result, Pid, Result} ->
            [] = Expected,
            Result;
        {'DOWN', Ref, process, Pid, Reason} ->
            ct:fail({worker_failed, Reason})
    after 10000 ->
        ct:fail({missing_continuations, Expected})
    end.

-spec cancelled(Function, Expected) -> Result when Function :: fun(() -> term()), Expected :: atom(), Result :: ok.
cancelled(Fun, Expected) ->
    with_trace(Fun, fun(Pid, Ref) -> cancel_at(Pid, Ref, Expected) end).

-spec cancel_at(Pid, Monitor, Expected) -> Result when
    Pid :: pid(), Monitor :: reference(), Expected :: atom(), Result :: ok.
cancel_at(Pid, Ref, Expected) ->
    receive
        {trace, Pid, out, {libdecaf_nif, Expected, 1}} ->
            exit(Pid, kill),
            receive
                {'DOWN', Ref, process, Pid, killed} -> ok;
                {'DOWN', Ref, process, Pid, Reason} -> ct:fail({not_cancelled, Reason})
            after 10000 -> ct:fail(cancellation_timeout)
            end;
        {trace, Pid, _, _} ->
            cancel_at(Pid, Ref, Expected);
        {result, Pid, _} ->
            ct:fail({completed_before_cancellation, Expected});
        {'DOWN', Ref, process, Pid, Reason} ->
            ct:fail({worker_failed, Reason})
    after 10000 ->
        ct:fail({missing_continuation, Expected})
    end.

-spec with_trace(Function, Check) -> Result when
    Function :: fun(() -> term()), Check :: fun((pid(), reference()) -> Value), Result :: Value.
with_trace(Fun, Check) ->
    Parent = self(),
    {Pid, Ref} = spawn_opt(
        fun() ->
            receive
                go -> Parent ! {result, self(), Fun()}
            end
        end,
        [monitor, {priority, low}]
    ),
    erlang:trace(Pid, true, [running]),
    Pid ! go,
    try
        Check(Pid, Ref)
    after
        exit(Pid, kill),
        erlang:demonitor(Ref, [flush]),
        flush_trace(Pid)
    end.

-spec flush_trace(Pid) -> Result when Pid :: pid(), Result :: ok.
flush_trace(Pid) ->
    receive
        {trace, Pid, _, _} -> flush_trace(Pid);
        {result, Pid, _} -> flush_trace(Pid)
    after 0 -> ok
    end.

-spec parallel_hash_parameters(Type, Length, Parameters) -> Result when
    Type :: atom(),
    Length :: non_neg_integer(),
    Parameters :: [binary() | pos_integer()],
    Result :: libdecaf:parallel_hash_parameters().
parallel_hash_parameters(Type, Length, [Key]) when
    (Type =:= hopmac128 orelse Type =:= hopmac256), is_binary(Key)
->
    {Type, Length, Key};
parallel_hash_parameters(Type, Length, [Key, Custom]) when
    (Type =:= hopmac128 orelse Type =:= hopmac256), is_binary(Key), is_binary(Custom)
->
    {Type, Length, Key, Custom};
parallel_hash_parameters(Type, Length, [Block]) when
    (Type =:= parallelhash128 orelse Type =:= parallelhash256), is_integer(Block), Block > 0
->
    {Type, Length, Block};
parallel_hash_parameters(Type, Length, [Block, Custom]) when
    (Type =:= parallelhash128 orelse Type =:= parallelhash256), is_integer(Block), Block > 0, is_binary(Custom)
->
    {Type, Length, Block, Custom}.

-spec parallel_xof_parameters(Type, Parameters) -> Result when
    Type :: atom(), Parameters :: [binary() | pos_integer()], Result :: libdecaf:parallel_xof_parameters().
parallel_xof_parameters(Type, [Key]) when
    (Type =:= hopmac128 orelse Type =:= hopmac256), is_binary(Key)
->
    {Type, Key};
parallel_xof_parameters(Type, [Key, Custom]) when
    (Type =:= hopmac128 orelse Type =:= hopmac256), is_binary(Key), is_binary(Custom)
->
    {Type, Key, Custom};
parallel_xof_parameters(Type, [Block]) when
    (Type =:= parallelhashxof128 orelse Type =:= parallelhashxof256), is_integer(Block), Block > 0
->
    {Type, Block};
parallel_xof_parameters(Type, [Block, Custom]) when
    (Type =:= parallelhashxof128 orelse Type =:= parallelhashxof256), is_integer(Block), Block > 0, is_binary(Custom)
->
    {Type, Block, Custom}.

-spec hash_parameters(Type, Length, Parameters) -> Result when
    Type :: atom(),
    Length :: non_neg_integer(),
    Parameters :: [binary() | pos_integer()],
    Result :: libdecaf:hash_parameters().
hash_parameters(Type, Length, Parameters) when
    Type =:= hopmac128; Type =:= hopmac256; Type =:= parallelhash128; Type =:= parallelhash256
->
    parallel_hash_parameters(Type, Length, Parameters);
hash_parameters(Type, Length, []) when
    Type =:= cshake128;
    Type =:= cshake256;
    Type =:= keccakxof_128;
    Type =:= keccakxof_256;
    Type =:= kt128;
    Type =:= kt256;
    Type =:= shake128;
    Type =:= shake256;
    Type =:= tuplehash128;
    Type =:= tuplehash256;
    Type =:= turboshake128;
    Type =:= turboshake256
->
    {Type, Length};
hash_parameters(Type, Length, [Custom]) when
    (Type =:= kt128 orelse Type =:= kt256 orelse Type =:= tuplehash128 orelse Type =:= tuplehash256), is_binary(Custom)
->
    {Type, Length, Custom};
hash_parameters(Type, Length, [Key]) when
    (Type =:= kmac128 orelse Type =:= kmac256), is_binary(Key)
->
    {Type, Length, Key};
hash_parameters(Type, Length, [Name, Custom]) when
    (Type =:= cshake128 orelse Type =:= cshake256 orelse Type =:= kmac128 orelse Type =:= kmac256),
    is_binary(Name),
    is_binary(Custom)
->
    {Type, Length, Name, Custom};
hash_parameters(Type, Length, [Domain]) when
    (Type =:= turboshake128 orelse Type =:= turboshake256), is_integer(Domain), Domain >= 1, Domain =< 127
->
    {Type, Length, Domain}.

-spec xof_parameters(Type, Parameters) -> Result when
    Type :: atom(), Parameters :: [binary() | pos_integer()], Result :: libdecaf:xof_parameters().
xof_parameters(Type, Parameters) when
    Type =:= hopmac128; Type =:= hopmac256; Type =:= parallelhashxof128; Type =:= parallelhashxof256
->
    parallel_xof_parameters(Type, Parameters);
xof_parameters(Type, []) when
    Type =:= cshake128;
    Type =:= cshake256;
    Type =:= keccakxof_128;
    Type =:= keccakxof_256;
    Type =:= kt128;
    Type =:= kt256;
    Type =:= shake128;
    Type =:= shake256;
    Type =:= tuplehashxof128;
    Type =:= tuplehashxof256;
    Type =:= turboshake128;
    Type =:= turboshake256
->
    Type;
xof_parameters(Type, [Custom]) when
    (Type =:= kt128 orelse Type =:= kt256 orelse Type =:= tuplehashxof128 orelse Type =:= tuplehashxof256),
    is_binary(Custom)
->
    {Type, Custom};
xof_parameters(Type, [Key]) when
    (Type =:= kmacxof128 orelse Type =:= kmacxof256), is_binary(Key)
->
    {Type, Key};
xof_parameters(Type, [Name, Custom]) when
    (Type =:= cshake128 orelse Type =:= cshake256 orelse Type =:= kmacxof128 orelse Type =:= kmacxof256),
    is_binary(Name),
    is_binary(Custom)
->
    {Type, Name, Custom};
xof_parameters(Type, [Domain]) when
    (Type =:= turboshake128 orelse Type =:= turboshake256), is_integer(Domain), Domain >= 1, Domain =< 127
->
    {Type, Domain}.
