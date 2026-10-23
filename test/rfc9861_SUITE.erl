%%% % @format
-module(rfc9861_SUITE).
-moduledoc """
All RFC 9861 TurboSHAKE and KangarooTwelve vectors through the Hash and XOF APIs.
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-include_lib("common_test/include/ct.hrl").
-export([
    all/0,
    turboshake_vectors/1,
    kt_vectors/1,
    kt_boundaries/1,
    kt_customization/1,
    domain_validation/1
]).
all() -> [turboshake_vectors, kt_vectors, kt_boundaries, kt_customization, domain_validation].

turboshake_vectors(Config) ->
    Vectors = vectors("turboshake.config", Config),
    31 = length(Vectors),
    lists:foreach(
        fun({Type, Message, Domain, Length, Offset, Hex}) ->
            Data = input(Message),
            Expected = binary:decode_hex(Hex),
            lists:foreach(
                fun(Module) ->
                    Output = Module:xof_turboshake(Type, Data, Length, Domain),
                    Expected = binary:part(Output, Offset, byte_size(Expected)),
                    State0 = Module:xof_init_turboshake(Type, Domain),
                    State1 = lists:foldl(
                        fun(Chunk, State) -> Module:xof_absorb(State, Chunk) end, State0, chunks(Data, 137)
                    ),
                    {_, Output} = Module:xof_squeeze(State1, Length),
                    {_, Output} = Module:xof_squeeze(State1, Length),
                    Output = Module:hash_turboshake(Type, Data, Length, Domain),
                    Hash = Module:hash_update(Module:hash_init_turboshake(Type, Length, Domain), Data),
                    Output = Module:hash_final(Hash)
                end,
                [libdecaf, libdecaf_nif]
            )
        end,
        Vectors
    ).

kt_vectors(Config) ->
    Vectors = vectors("kt.config", Config),
    36 = length(Vectors),
    lists:foreach(
        fun({Type, Message, Customization, Length, Offset, Hex}) ->
            Data = input(Message),
            Custom = input(Customization),
            Expected = binary:decode_hex(Hex),
            lists:foreach(
                fun(Module) ->
                    Output = Module:xof_kt(Type, Data, Length, [Custom]),
                    Expected = binary:part(Output, Offset, byte_size(Expected)),
                    State0 = Module:xof_init_kt(Type, [Custom]),
                    State1 = lists:foldl(
                        fun(Chunk, State) -> Module:xof_absorb(State, Chunk) end, State0, chunks(Data, 137)
                    ),
                    {_, Output} = Module:xof_squeeze(State1, Length),
                    {_, Output} = Module:xof_squeeze(State1, Length),
                    Output = Module:hash_kt(Type, Data, Length, Custom),
                    Hash = Module:hash_update(Module:hash_init_kt(Type, Length, Custom), Data),
                    Output = Module:hash_final(Hash)
                end,
                [libdecaf, libdecaf_nif]
            )
        end,
        Vectors
    ).

kt_boundaries(_) ->
    lists:foreach(
        fun(Type) ->
            lists:foreach(
                fun(Length) ->
                    Data = input({pattern, Length}),
                    lists:foreach(
                        fun(CustomLength) ->
                            Custom = input({pattern, CustomLength}),
                            State0 = libdecaf:xof_init_kt(Type, Custom),
                            State1 = lists:foldl(
                                fun(Chunk, State) -> libdecaf:xof_absorb(State, Chunk) end, State0, chunks(Data, 137)
                            ),
                            Expected = libdecaf:xof_kt(Type, Data, 200, Custom),
                            {Next, A} = libdecaf:xof_squeeze(State1, 1),
                            {_, B} = libdecaf:xof_squeeze(Next, 199),
                            Expected = <<A/binary, B/binary>>
                        end,
                        [0, 1, 255, 256, 8189, 8190]
                    )
                end,
                [8190, 8191, 8192, 8193, 16383, 16384, 16385]
            )
        end,
        [kt128, kt256]
    ).

kt_customization(_) ->
    lists:foreach(
        fun(Type) ->
            Message = input({pattern, 65539}),
            Custom = input({pattern, 200001}),
            State = libdecaf:xof_absorb(libdecaf:xof_init_kt(Type, [[], Custom]), Message),
            Expected = libdecaf:xof_kt(Type, Message, 131073, Custom),
            {_, Expected} = libdecaf:xof_squeeze(State, 131073),
            {_, Expected} = libdecaf:xof_squeeze(State, 131073),
            EmptyCustom = libdecaf:xof_kt(Type, Message, 131073),
            true = EmptyCustom =/= Expected,
            {Next, <<>>} = libdecaf:xof_squeeze(State, 0),
            badarg(fun() -> libdecaf:xof_absorb(Next, <<>>) end),
            badarg(fun() -> libdecaf:xof_init_kt(Type, invalid) end),
            badarg(fun() -> libdecaf:hash_init_kt(Type, 32, 31) end)
        end,
        [kt128, kt256]
    ).

domain_validation(_) ->
    lists:foreach(
        fun(Type) ->
            lists:foreach(
                fun(Domain) ->
                    badarg(fun() -> libdecaf:xof_turboshake(Type, <<>>, 32, Domain) end),
                    badarg(fun() -> libdecaf:xof_init_turboshake(Type, Domain) end),
                    badarg(fun() -> libdecaf:hash_init_turboshake(Type, 32, Domain) end)
                end,
                [-1, 0, 128, 256, <<31>>, invalid]
            ),
            Expected = libdecaf:xof_turboshake(Type, <<"abc">>, 32),
            Expected = libdecaf:xof_turboshake(Type, <<"abc">>, 32, 16#1F)
        end,
        [turboshake128, turboshake256]
    ).

badarg(Fun) ->
    try Fun() of
        Result -> ct:fail({expected_badarg, Result})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

chunks(<<Chunk:137/binary, Rest/binary>>, 137) -> [Chunk | chunks(Rest, 137)];
chunks(Tail, _) -> [Tail].

input({pattern, Length}) ->
    Pattern = list_to_binary(lists:seq(0, 250)),
    Whole = binary:copy(Pattern, Length div 251),
    Tail = binary:part(Pattern, 0, Length rem 251),
    <<Whole/binary, Tail/binary>>;
input({repeat, Byte, Length}) ->
    binary:copy(<<Byte>>, Length);
input(Hex) ->
    binary:decode_hex(Hex).

vectors(File, Config) ->
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), File)),
    Vectors.
