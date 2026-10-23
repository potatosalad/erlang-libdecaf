%%% % @format
-module(sp800185_SUITE).
-moduledoc """
NIST SP 800-185 primitives and Revision 1 streaming contracts.
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-include_lib("common_test/include/ct.hrl").
-export([
    all/0,
    documentation/1,
    kmac_draft_vectors/1,
    kmac_invalid/1,
    kmac_length_binding/1,
    kmac_nist_vectors/1,
    kmac_reference/1,
    kmac_trapping/1,
    kmac_upgrade/1,
    xof_streaming/1
]).

all() ->
    [
        kmac_draft_vectors,
        kmac_nist_vectors,
        kmac_length_binding,
        kmac_reference,
        kmac_invalid,
        kmac_trapping,
        kmac_upgrade,
        xof_streaming,
        documentation
    ].

kmac_draft_vectors(Config) ->
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), "draft.config")),
    18 = length(Vectors),
    18 = length(lists:usort([Name || {Name, _, _, _, _, _, _} <- Vectors])),
    lists:foreach(
        fun({_Name, Type, Kind, KeyHex, DataHex, CustomHex, TagHex}) ->
            Key = binary:decode_hex(KeyHex),
            Input = binary:decode_hex(DataHex),
            Data =
                case Kind of
                    kdf -> <<Input/binary, 1>>;
                    _ -> Input
                end,
            check_kmac(Type, Key, Data, binary:decode_hex(CustomHex), binary:decode_hex(TagHex))
        end,
        Vectors
    ).

kmac_nist_vectors(Config) ->
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), "nist.config")),
    6 = length(Vectors),
    lists:foreach(
        fun({_Name, Type, nist, Key, Data, Custom, Tag}) ->
            check_kmac(
                Type,
                binary:decode_hex(Key),
                binary:decode_hex(Data),
                binary:decode_hex(Custom),
                binary:decode_hex(Tag)
            )
        end,
        Vectors
    ).

check_kmac(Type, Key, Data, Custom, Expected) ->
    Length = byte_size(Expected),
    lists:foreach(
        fun(Module) ->
            Expected = Module:kmac(Type, [Key], [Data], Length, [Custom]),
            Initial = Module:kmac_init(Type, [Key], [Custom]),
            Split = byte_size(Data) div 2,
            <<First:Split/binary, Last/binary>> = Data,
            State = Module:kmac_update(Module:kmac_update(Initial, [First]), Last),
            Expected = Module:kmac_final(State, Length),
            Expected = Module:kmac_final(State, Length),
            <<>> = Module:kmac_final(State, 0),
            case Custom of
                <<>> ->
                    Expected = Module:kmac(Type, Key, Data, Length),
                    Default = Module:kmac_update(Module:kmac_init(Type, Key), Data),
                    Expected = Module:kmac_final(Default, Length);
                _ ->
                    ok
            end
        end,
        [libdecaf, libdecaf_nif]
    ).

kmac_length_binding(_) ->
    %% draft-ietf-ipsecme-sha3-02, Table 4: the 16-byte tag is not a prefix.
    Short = binary:decode_hex(<<"E6AFF27FEF95903EB939BC3745730D34">>),
    Prefix = binary:decode_hex(<<"5C135C615152FB4D9784DD1155F9B603">>),
    State = libdecaf:kmac_init(kmac128, <<>>),
    Short = libdecaf:kmac_final(State, 16),
    Long = libdecaf:kmac_final(State, 32),
    Prefix = binary:part(Long, 0, 16),
    true = Short =/= Prefix.

kmac_reference(_) ->
    lists:foreach(
        fun({Type, CShake, Rate}) ->
            lists:foreach(
                fun(Length) ->
                    Key = binary:copy(<<42>>, Length),
                    Custom = binary:copy(<<17>>, Length),
                    Data = binary:copy(<<123>>, Length),
                    FramedKey = bytepad([left_encode(byte_size(Key) * 8), Key], Rate),
                    lists:foreach(
                        fun(OutputLength) ->
                            Expected = libdecaf:xof_cshake(
                                CShake,
                                [FramedKey, Data, right_encode(OutputLength * 8)],
                                OutputLength,
                                <<"KMAC">>,
                                Custom
                            ),
                            check_kmac(Type, Key, Data, Custom, Expected)
                        end,
                        [0, 16, 32, 255, 256]
                    ),
                    Initial = libdecaf:kmac_init(Type, Key, Custom),
                    Empty = libdecaf:kmac(Type, Key, <<>>, 32, Custom),
                    First = libdecaf:kmac_update(Initial, <<"first">>),
                    Second = libdecaf:kmac_update(Initial, <<"second">>),
                    Empty = libdecaf:kmac_final(Initial, 32),
                    true = libdecaf:kmac_final(First, 32) =/= libdecaf:kmac_final(Second, 32)
                end,
                [0, 1, 31, 32, Rate - 4, Rate - 3, Rate - 1, Rate, Rate + 1, 65537]
            )
        end,
        [{kmac128, cshake128, 168}, {kmac256, cshake256, 136}]
    ).

kmac_invalid(_) ->
    lists:foreach(
        fun(Module) ->
            State = Module:kmac_init(kmac128, <<>>),
            lists:foreach(fun badarg/1, [
                fun() -> Module:kmac(shake128, <<>>, <<>>, 32) end,
                fun() -> Module:kmac(kmac128, invalid, <<>>, 32) end,
                fun() -> Module:kmac(kmac128, <<>>, [256], 32) end,
                fun() -> Module:kmac(kmac128, <<>>, <<>>, -1) end,
                fun() -> Module:kmac(kmac128, <<>>, <<>>, 1 bsl 61) end,
                fun() -> Module:kmac(kmac128, <<>>, <<>>, 32, invalid) end,
                fun() -> Module:kmac_init(kmac128, invalid) end,
                fun() -> Module:kmac_init(kmac128, <<>>, [256]) end,
                fun() -> Module:kmac_init(sha3_256, <<>>) end,
                fun() -> Module:kmac_update(State, [256]) end,
                fun() -> Module:kmac_update(make_ref(), <<>>) end,
                fun() -> Module:kmac_final(State, -1) end,
                fun() -> Module:kmac_final(State, 1 bsl 61) end,
                fun() -> Module:kmac_final(make_ref(), 32) end,
                fun() -> Module:kmac_final(libdecaf_nif:hash_init(sha3_256), 32) end,
                fun() -> Module:kmac_update(libdecaf_nif:xof_cshake_init(cshake128), <<>>) end,
                fun() -> Module:hash_update(State, <<>>) end,
                fun() -> Module:xof_cshake_final(State, 32) end
            ])
        end,
        [libdecaf, libdecaf_nif]
    ).

kmac_trapping(_) ->
    Large = binary:copy(<<42>>, 1000001),
    Absorb = libdecaf_nif_kmac_absorb_continue,
    Squeeze = libdecaf_nif_kmac_squeeze_continue,
    lists:foreach(
        fun(Type) ->
            Initial = traced(fun() -> libdecaf:kmac_init(Type, Large, Large) end, [Absorb]),
            State = traced(fun() -> libdecaf:kmac_update(Initial, Large) end, [Absorb]),
            Expected = libdecaf:kmac(Type, Large, Large, 65537, Large),
            Expected = traced(fun() -> libdecaf:kmac_final(State, 65537) end, [Squeeze]),
            Expected = traced(fun() -> libdecaf:kmac(Type, Large, Large, 65537, Large) end, [Absorb, Squeeze]),
            lists:foreach(fun({Fun, Continuation}) -> cancelled(Fun, Continuation) end, [
                {fun() -> libdecaf:kmac_init(Type, Large, Large) end, Absorb},
                {fun() -> libdecaf:kmac_update(Initial, Large) end, Absorb},
                {fun() -> libdecaf:kmac_final(State, 8000001) end, Squeeze}
            ]),
            Expected = libdecaf:kmac_final(State, 65537)
        end,
        [kmac128, kmac256]
    ).

kmac_upgrade(_) ->
    State = libdecaf:kmac_update(libdecaf:kmac_init(kmac128, <<"key">>), <<"abc">>),
    Expected = libdecaf:kmac_final(State, 32),
    {libdecaf_nif, Binary, Filename} = code:get_object_code(libdecaf_nif),
    {module, libdecaf_nif} = code:load_binary(libdecaf_nif, Filename, Binary),
    Expected = libdecaf:kmac_final(State, 32),
    Expected = libdecaf:kmac(kmac128, <<"key">>, <<"abc">>, 32).

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

xof_streaming(_) ->
    Groups = [
        {xof_cshake, cshake128},
        {xof_cshake, cshake256},
        {xof_keccak, keccak_xof_128},
        {xof_keccak, keccak_xof_256},
        {xof_kt, kt128},
        {xof_kt, kt256},
        {xof_sha3, shake128},
        {xof_sha3, shake256},
        {xof_turboshake, turboshake128},
        {xof_turboshake, turboshake256}
    ],
    Lengths = [0, 1, 31, 32, 135, 136, 137, 167, 168, 169, 20001, 65537],
    lists:foreach(
        fun(Module) ->
            lists:foreach(
                fun({Group, Algorithm}) ->
                    Call = fun(Suffix, Arguments) ->
                        apply(Module, list_to_atom(atom_to_list(Group) ++ Suffix), Arguments)
                    end,
                    Initial = Call("_init", [Algorithm]),
                    First = Call("_absorb", [Initial, <<"a">>]),
                    State = Call("_update", [First, [<<"b">>, <<"c">>]]),
                    Expected = Call("", [Algorithm, <<"abc">>, lists:sum(Lengths)]),
                    {_, Parts} = lists:foldl(
                        fun(Length, {Current, Acc}) ->
                            {Next, Output} = Call("_squeeze", [Current, Length]),
                            Length = byte_size(Output),
                            {_, Output} = Call("_squeeze", [Current, Length]),
                            badarg(fun() -> Call("_absorb", [Next, <<>>]) end),
                            badarg(fun() -> Call("_update", [Next, <<"more">>]) end),
                            {Next, [Output | Acc]}
                        end,
                        {State, []},
                        Lengths
                    ),
                    Expected = iolist_to_binary(lists:reverse(Parts)),
                    Expected = Call("_final", [State, lists:sum(Lengths)]),
                    Empty = Call("", [Algorithm, <<>>, 32]),
                    {_, Empty} = Call("_squeeze", [Initial, 32]),
                    badarg(fun() -> Call("_squeeze", [State, -1]) end),
                    badarg(fun() -> Call("_squeeze", [make_ref(), 1]) end),
                    badarg(fun() -> Call("_absorb", [libdecaf_nif:hash_init(sha3_256), <<>>]) end)
                end,
                Groups
            ),
            Initial = Module:xof_kt_absorb(Module:xof_kt_init(kt128), <<"abc">>),
            Custom = binary:copy(<<42>>, 65537),
            {FirstState, FirstOutput} = Module:xof_kt_squeeze(Initial, 32, Custom),
            {_, SecondOutput} = Module:xof_kt_squeeze(FirstState, 32),
            Whole = Module:xof_kt(kt128, <<"abc">>, 64, Custom),
            Whole = <<FirstOutput/binary, SecondOutput/binary>>,
            badarg(fun() -> Module:xof_kt_squeeze(FirstState, 32, <<>>) end),
            badarg(fun() -> Module:xof_kt_final(FirstState, 32, <<>>) end)
        end,
        [libdecaf, libdecaf_nif]
    ),
    State = libdecaf:xof_cshake_absorb(libdecaf:xof_cshake_init(cshake128), <<"abc">>),
    {_, Output} = traced(
        fun() -> libdecaf:xof_cshake_squeeze(State, 1000001) end,
        [libdecaf_nif_xof_cshake_squeeze_continue]
    ),
    Output = libdecaf:xof_cshake(cshake128, <<"abc">>, 1000001),
    cancelled(
        fun() -> libdecaf:xof_cshake_squeeze(State, 8000001) end,
        libdecaf_nif_xof_cshake_squeeze_continue
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
