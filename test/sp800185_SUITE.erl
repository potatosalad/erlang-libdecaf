%%% % @format
-module(sp800185_SUITE).
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

kmac_draft_vectors(Config) ->
    Vectors = vectors("draft.config", Config),
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
    ).

nist_vectors(Config) ->
    lists:foreach(
        fun({File, Xof}) ->
            Records = vectors(File, Config),
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
        [{"nist.config", false}, {"kmac_xof.config", true}]
    ),
    lists:foreach(
        fun({File, Family}) ->
            Records = vectors(File, Config),
            12 = length(Records),
            lists:foreach(
                fun(Record) ->
                    case Record of
                        {_Name, Type, Xof, Elements, Custom, Output} ->
                            check(
                                Family,
                                selector(Type, Xof),
                                [binary:decode_hex(E) || E <- Elements],
                                [binary:decode_hex(Custom)],
                                binary:decode_hex(Output),
                                Xof
                            );
                        {_Name, Type, Xof, Size, Data, Custom, Output} ->
                            check(
                                Family,
                                selector(Type, Xof),
                                binary:decode_hex(Data),
                                [Size, binary:decode_hex(Custom)],
                                binary:decode_hex(Output),
                                Xof
                            )
                    end
                end,
                Records
            )
        end,
        [{"tuplehash.config", tuplehash}, {"parallelhash.config", parallelhash}]
    ).

selector(Type, false) -> Type;
selector(Type, true) -> list_to_atom(re:replace(atom_to_list(Type), "(128|256)$", "xof\\1", [{return, list}])).

check(Family, Type, Input, Parameters, Expected, Xof) ->
    Mode =
        case Xof of
            true -> "xof";
            false -> "hash"
        end,
    Once = list_to_atom(Mode ++ "_" ++ atom_to_list(Family)),
    Init = list_to_atom(Mode ++ "_init_" ++ atom_to_list(Family)),
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
    lists:foreach(
        fun(Module) ->
            Expected = apply(Module, Once, [Type, Input, Length | Parameters]),
            Initial = apply(Module, Init, InitArgs),
            true = is_reference(Initial),
            GenericInit =
                case Xof of
                    true -> xof_init;
                    false -> hash_init
                end,
            Generic = apply(Module, GenericInit, [list_to_tuple(InitArgs)]),
            Chunks =
                case Family of
                    tuplehash -> Input;
                    _ -> chunks(iolist_to_binary(Input), 137)
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
                            Expected = libdecaf:xof_cshake(
                                Cshake, [EncodedKey, Data, right_encode(Bits)], Length, <<"KMAC">>, Custom
                            ),
                            check(kmac, selector(Kmac, Xof), Data, [Key, Custom], Expected, Xof),
                            TupleExpected = libdecaf:xof_cshake(
                                Cshake, [EncodedElements, right_encode(Bits)], Length, <<"TupleHash">>, Custom
                            ),
                            check(tuplehash, selector(Tuple, Xof), Elements, [Custom], TupleExpected, Xof),
                            B = 8,
                            Leaves = chunks_nonempty(Data, B),
                            CVs = [libdecaf:xof_sha3(Shake, Leaf, 200 - Rate) || Leaf <- Leaves],
                            ParallelExpected = libdecaf:xof_cshake(
                                Cshake,
                                [left_encode(B), CVs, right_encode(length(Leaves)), right_encode(Bits)],
                                Length,
                                <<"ParallelHash">>,
                                Custom
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
    ).

tuple_boundaries(_) ->
    lists:foreach(
        fun({Hash, Xof}) ->
            A = libdecaf:hash_tuplehash(Hash, [<<"a">>, <<"bc">>], 32),
            B = libdecaf:hash_tuplehash(Hash, [<<"ab">>, <<"c">>], 32),
            true = A =/= B,
            true = libdecaf:hash_tuplehash(Hash, [], 32) =/= libdecaf:hash_tuplehash(Hash, [<<>>], 32),
            true = libdecaf:xof_tuplehash(Xof, [], 32) =/= libdecaf:xof_tuplehash(Xof, [<<>>], 32),
            State = libdecaf:hash_init_tuplehash(Hash, 32),
            A = libdecaf:hash_final(libdecaf:hash_update(libdecaf:hash_update(State, <<"a">>), <<"bc">>)),
            false = libdecaf:hash_final(State) =:= A
        end,
        [{tuplehash128, tuplehashxof128}, {tuplehash256, tuplehashxof256}]
    ).

parallel_boundaries(_) ->
    lists:foreach(
        fun(Type) ->
            lists:foreach(
                fun(B) ->
                    lists:foreach(
                        fun(Size) ->
                            Input = binary:copy(<<42>>, Size),
                            Expected = libdecaf:hash_parallelhash(Type, Input, 32, B, <<"blocks">>),
                            check(parallelhash, Type, Input, [B, <<"blocks">>], Expected, false)
                        end,
                        lists:usort([0, 1, B - 1, B, B + 1, 2 * B, 2 * B + 1])
                    )
                end,
                [1, 2, 7, 8, 12, 136, 168, 257, 65537]
            ),
            true =
                libdecaf:hash_parallelhash(Type, <<"abcdefghijk">>, 32, 8) =/=
                    libdecaf:hash_parallelhash(Type, <<"abcdefghijk">>, 32, 9)
        end,
        [parallelhash128, parallelhash256]
    ).

length_binding(_) ->
    lists:foreach(
        fun({Family, Type, Input, Parameters}) ->
            Name = list_to_atom("hash_" ++ atom_to_list(Family)),
            Short = apply(libdecaf, Name, [Type, Input, 16 | Parameters]),
            Long = apply(libdecaf, Name, [Type, Input, 32 | Parameters]),
            true = Short =/= binary:part(Long, 0, 16),
            Xof = list_to_atom("xof_" ++ atom_to_list(Family)),
            XofShort = apply(libdecaf, Xof, [selector(Type, true), Input, 16 | Parameters]),
            XofLong = apply(libdecaf, Xof, [selector(Type, true), Input, 32 | Parameters]),
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
    <<"E6AFF27FEF95903EB939BC3745730D34">> = binary:encode_hex(libdecaf:hash_kmac(kmac128, <<>>, 16, <<>>)).

hopmac_reference(_) ->
    %% RFC 9861 section 4: KT(Key, KT(Message, Customization, 32/64), Length).
    lists:foreach(
        fun({Type, KT, InnerLength}) ->
            lists:foreach(
                fun(Size) ->
                    Key = binary:copy(<<42>>, Size),
                    Message = binary:copy(<<19>>, Size),
                    Custom = binary:copy(<<17>>, Size),
                    Digest = libdecaf:xof_kt(KT, Message, InnerLength, Custom),
                    Expected = libdecaf:xof_kt(KT, Key, 169, Digest),
                    check(hopmac, Type, Message, [Key, Custom], Expected, false),
                    check(hopmac, Type, Message, [Key, Custom], Expected, true)
                end,
                [0, 1, 32, 69, 8191, 8192, 8193, 65537]
            )
        end,
        [{hopmac128, kt128, 32}, {hopmac256, kt256, 64}]
    ).

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
                    Name = list_to_atom(
                        case Mode of
                            true -> "xof_";
                            false -> "hash_"
                        end ++ atom_to_list(Family)
                    ),
                    Input =
                        case Family of
                            tuplehash -> [<<"message">>];
                            _ -> <<"message">>
                        end,
                    Expected = apply(libdecaf, Name, [Type, Input, 32 | Parameters]),
                    check(Family, Type, Input, Parameters, Expected, Mode)
                end,
                [false, true]
            )
        end,
        families()
    ).

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

invalid_arguments(_) ->
    lists:foreach(
        fun(Module) ->
            Hash = Module:hash_init_sha3(sha3_256),
            Xof = Module:xof_init_sha3(shake128),
            lists:foreach(fun badarg/1, [
                fun() -> Module:hash_init_cshake(cshake128, -1) end,
                fun() -> Module:hash_init_kmac(kmacxof128, 32, <<>>) end,
                fun() -> Module:xof_init_kmac(kmac128, <<>>) end,
                fun() -> Module:hash_init_parallelhash(parallelhash128, 32, 0) end,
                fun() -> Module:xof_init_parallelhash(parallelhashxof128, -1) end,
                fun() -> Module:hash_init_turboshake(turboshake128, 32, <<31>>) end,
                fun() -> Module:xof_init_turboshake(turboshake128, 0) end,
                fun() -> Module:hash_init_kt(kt128, 32, invalid) end,
                fun() -> Module:xof_init_hopmac(hopmac128, invalid) end,
                fun() -> Module:hash_init_kmac(kmac128, 1 bsl 61, <<>>) end,
                fun() -> Module:hash_init_sha3(shake128) end,
                fun() -> Module:hash_init_sha3(sha3_224, 29) end,
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
                fun() -> Module:hash_tuplehash(tuplehash128, [<<>> | invalid], 32) end,
                fun() -> Module:xof_tuplehash(tuplehashxof128, <<"flattened">>, 32) end,
                fun() -> Module:xof_absorb(make_ref(), <<>>) end
            ])
        end,
        [libdecaf, libdecaf_nif]
    ).

trapping(_) ->
    Large = binary:copy(<<42>>, 200001),
    lists:foreach(
        fun({Family, Hash, Xof, Parameters}) ->
            P = "libdecaf_nif_" ++ atom_to_list(Family),
            Absorb = list_to_atom(P ++ "_absorb_continue"),
            Squeeze = list_to_atom(P ++ "_squeeze_continue"),
            Name = list_to_atom("hash_" ++ atom_to_list(Family)),
            Data =
                case Family of
                    tuplehash -> [Large, <<>>];
                    _ -> Large
                end,
            _ = traced(fun() -> apply(libdecaf, Name, [Hash, Data, 65537 | Parameters]) end, [Absorb, Squeeze]),
            Init = list_to_atom("xof_init_" ++ atom_to_list(Family)),
            State0 = apply(libdecaf, Init, [Xof | Parameters]),
            State1 = traced(fun() -> libdecaf:xof_absorb(State0, Large) end, [Absorb]),
            {_Next, Output} = traced(fun() -> libdecaf:xof_squeeze(State1, 65537) end, [Squeeze]),
            65537 = byte_size(Output)
        end,
        families()
    ),
    Empty = lists:duplicate(100001, <<>>),
    _ = traced(fun() -> libdecaf:hash_tuplehash(tuplehash128, Empty, 32) end, [libdecaf_nif_tuplehash_absorb_continue]),
    _ = traced(fun() -> libdecaf:hash_parallelhash(parallelhash128, Large, 32, 1) end, [
        libdecaf_nif_parallelhash_absorb_continue
    ]).

cancellation(_) ->
    Large = binary:copy(<<42>>, 1000001),
    lists:foreach(
        fun({Family, _Hash, Xof, Parameters}) ->
            Init = list_to_atom("xof_init_" ++ atom_to_list(Family)),
            State = apply(libdecaf, Init, [Xof | Parameters]),
            P = "libdecaf_nif_" ++ atom_to_list(Family),
            cancelled(fun() -> libdecaf:xof_absorb(State, Large) end, list_to_atom(P ++ "_absorb_continue")),
            cancelled(fun() -> libdecaf:xof_squeeze(State, 8000001) end, list_to_atom(P ++ "_squeeze_continue"))
        end,
        families()
    ),
    cancelled(
        fun() -> libdecaf:xof_init_hopmac(hopmac128, Large, Large) end,
        libdecaf_nif_hopmac_absorb_continue
    ),
    cancelled(
        fun() -> libdecaf:hash_init_kmac(kmac128, 32, Large, Large) end,
        libdecaf_nif_kmac_absorb_continue
    ),
    KT = libdecaf:xof_init_kt(kt128, Large),
    cancelled(fun() -> libdecaf:xof_squeeze(KT, 32) end, libdecaf_nif_kt_absorb_continue),
    erlang:garbage_collect().

upgrade(_) ->
    States = [
        begin
            HashInit = list_to_atom("hash_init_" ++ atom_to_list(Family)),
            XofInit = list_to_atom("xof_init_" ++ atom_to_list(Family)),
            Hash = libdecaf:hash_update(apply(libdecaf, HashInit, [H, 32 | Parameters]), <<"abc">>),
            Xof = libdecaf:xof_absorb(apply(libdecaf, XofInit, [X | Parameters]), <<"abc">>),
            {Advanced, First} = libdecaf:xof_squeeze(Xof, 16),
            {_, Last} = libdecaf:xof_squeeze(Advanced, 16),
            {Hash, libdecaf:hash_final(Hash), Xof, Advanced, First, Last}
        end
     || {Family, H, X, Parameters} <- families()
    ],
    {Module, Binary, Filename} = code:get_object_code(libdecaf_nif),
    {module, Module} = code:load_binary(Module, Filename, Binary),
    lists:foreach(
        fun({Hash, Digest, Xof, Advanced, First, Last}) ->
            Digest = libdecaf:hash_final(Hash),
            {_, First} = libdecaf:xof_squeeze(Xof, 16),
            {_, Last} = libdecaf:xof_squeeze(Advanced, 16),
            badarg(fun() -> libdecaf:xof_absorb(Advanced, <<>>) end)
        end,
        States
    ),
    true = code:soft_purge(libdecaf_nif).

vectors(File, Config) ->
    {ok, Records} = file:consult(filename:join(?config(data_dir, Config), File)),
    Records.

encode_string(Binary) -> [left_encode(byte_size(Binary) * 8), Binary].
chunks(<<>>, _) -> [<<>>];
chunks(Input, Size) -> chunks_nonempty(Input, Size).
chunks_nonempty(<<>>, _) ->
    [];
chunks_nonempty(Input, Size) when byte_size(Input) =< Size -> [Input];
chunks_nonempty(Input, Size) ->
    <<Head:Size/binary, Tail/binary>> = Input,
    [Head | chunks_nonempty(Tail, Size)].

documentation(_) ->
    {ok, {docs_v1, _, erlang, <<"text/markdown">>, _, _, Entries}} = code:get_doc(libdecaf),
    lists:foreach(
        fun
            ({{function, _, _}, _, _, #{<<"en">> := Doc}, _}) ->
                case re:run(Doc, <<"```erlang\\n(.*?)```">>, [global, dotall, {capture, [1], binary}]) of
                    {match, Examples} ->
                        lists:foreach(
                            fun([Example]) ->
                                {ok, Tokens, _} = erl_scan:string(unicode:characters_to_list(Example)),
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
    ).

left_encode(Integer) ->
    Bytes = binary:encode_unsigned(Integer),
    <<(byte_size(Bytes)), Bytes/binary>>.

right_encode(Integer) ->
    Bytes = binary:encode_unsigned(Integer),
    <<Bytes/binary, (byte_size(Bytes))>>.

bytepad(Input, Width) ->
    Binary = iolist_to_binary([left_encode(Width), Input]),
    Padding = (Width - byte_size(Binary) rem Width) rem Width,
    <<Binary/binary, 0:(Padding * 8)>>.

badarg(Fun) ->
    try Fun() of
        Value -> ct:fail({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

traced(Fun, Expected) ->
    with_trace(Fun, fun(Pid, Ref) -> trace_result(Pid, Ref, Expected) end).

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

cancelled(Fun, Expected) ->
    with_trace(Fun, fun(Pid, Ref) -> cancel_at(Pid, Ref, Expected) end).

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

flush_trace(Pid) ->
    receive
        {trace, Pid, _, _} -> flush_trace(Pid);
        {result, Pid, _} -> flush_trace(Pid)
    after 0 -> ok
    end.
