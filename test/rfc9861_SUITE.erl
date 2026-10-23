%%% % @format
-module(rfc9861_SUITE).
-moduledoc """
RFC 9861 TurboSHAKE and KangarooTwelve test vectors.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    domain_validation/1,
    immutable_states/1,
    kt_boundaries/1,
    kt_customization/1,
    kt_vectors/1,
    turboshake_vectors/1
]).

all() ->
    [
        turboshake_vectors,
        kt_vectors,
        kt_boundaries,
        kt_customization,
        domain_validation,
        immutable_states
    ].

domain_validation(_) ->
    lists:foreach(
        fun(Type) ->
            lists:foreach(
                fun(Domain) ->
                    badarg(fun() -> libdecaf:xof_turboshake(Type, <<>>, 32, Domain) end),
                    badarg(fun() -> libdecaf:xof_turboshake_init(Type, Domain) end)
                end,
                [-1, 0, 128, 256, <<31>>, invalid]
            ),
            Expected = libdecaf:xof_turboshake(Type, <<"abc">>, 32),
            Expected = libdecaf:xof_turboshake(Type, <<"abc">>, 32, 16#1f)
        end,
        [turboshake128, turboshake256]
    ),
    badarg(fun() -> libdecaf:xof_turboshake(shake128, <<>>, 32, 31) end),
    badarg(fun() -> libdecaf:xof_turboshake_init(cshake128, 31) end).

immutable_states(_) ->
    lists:foreach(
        fun(Type) ->
            State = libdecaf:xof_turboshake_init(Type, 127),
            true = is_reference(State),
            Empty = libdecaf:xof_turboshake(Type, <<>>, 200, 127),
            One = libdecaf:xof_turboshake_update(State, <<"one">>),
            Two = libdecaf:xof_turboshake_update(State, <<"two">>),
            Empty = libdecaf:xof_turboshake_final(State, 200),
            Expected = libdecaf:xof_turboshake(Type, <<"one">>, 200, 127),
            Expected = libdecaf:xof_turboshake_final(One, 200),
            Expected = libdecaf:xof_turboshake_final(One, 200),
            Other = libdecaf:xof_turboshake(Type, <<"two">>, 200, 127),
            Other = libdecaf:xof_turboshake_final(Two, 200),
            <<>> = libdecaf:xof_turboshake_final(State, 0)
        end,
        [turboshake128, turboshake256]
    ).

kt_boundaries(_) ->
    lists:foreach(
        fun(Type) ->
            lists:foreach(
                fun(Length) ->
                    Message = input({pattern, Length}),
                    State = libdecaf:xof_kt_init(Type),
                    Updated = lists:foldl(
                        fun(Chunk, Acc) -> libdecaf:xof_kt_update(Acc, Chunk) end,
                        State,
                        chunks(Message, 137)
                    ),
                    lists:foreach(
                        fun(CustomLength) ->
                            Custom = input({pattern, CustomLength}),
                            Expected = libdecaf:xof_kt(Type, [Message], 200, [Custom]),
                            Expected = libdecaf:xof_kt_final(Updated, 200, Custom),
                            Expected = libdecaf:xof_kt_final(Updated, 200, Custom)
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
            State = libdecaf:xof_kt_update(libdecaf:xof_kt_init(Type), Message),
            Expected = libdecaf:xof_kt(Type, Message, 131073, [Custom]),
            Expected = libdecaf:xof_kt_final(State, 131073, [[], Custom]),
            Expected = libdecaf:xof_kt_final(State, 131073, Custom),
            EmptyCustom = libdecaf:xof_kt(Type, Message, 131073),
            EmptyCustom = libdecaf:xof_kt_final(State, 131073),
            OtherCustom = libdecaf:xof_kt(Type, Message, 32, <<"other">>),
            OtherCustom = libdecaf:xof_kt_final(State, 32, <<"other">>),
            <<>> = libdecaf:xof_kt_final(State, 0, Custom),
            badarg(fun() -> libdecaf:xof_kt(Type, <<>>, 32, invalid) end),
            badarg(fun() -> libdecaf:xof_kt(Type, <<>>, 32, 31) end),
            badarg(fun() -> libdecaf:xof_kt_final(State, 32, invalid) end),
            badarg(fun() -> libdecaf:xof_kt_final(State, -1, <<>>) end),
            badarg(fun() -> libdecaf:xof_turboshake_init(Type, 31) end)
        end,
        [kt128, kt256]
    ),
    ShakeState = libdecaf:xof_turboshake_init(turboshake128),
    badarg(fun() -> libdecaf:xof_kt_final(ShakeState, 32, <<>>) end).

kt_vectors(Config) ->
    Vectors = vectors("kt.config", Config),
    36 = length(Vectors),
    lists:foreach(
        fun({Type, Message, Customization, Length, Offset, Hex}) ->
            Input = input(Message),
            Custom = input(Customization),
            Expected = binary:decode_hex(Hex),
            Output = libdecaf:xof_kt(Type, Input, Length, [Custom]),
            Expected = binary:part(Output, Offset, byte_size(Expected)),
            Split = byte_size(Input) div 2,
            <<First:Split/binary, Last/binary>> = Input,
            State = libdecaf:xof_kt_init(Type),
            Updated = libdecaf:xof_kt_update(libdecaf:xof_kt_update(State, First), Last),
            Output = libdecaf:xof_kt_final(Updated, Length, Custom),
            case Custom of
                <<>> ->
                    Output = libdecaf:xof_kt(Type, Input, Length),
                    Output = libdecaf:xof_kt_final(Updated, Length);
                _ ->
                    ok
            end
        end,
        Vectors
    ).

turboshake_vectors(Config) ->
    Vectors = vectors("turboshake.config", Config),
    31 = length(Vectors),
    lists:foreach(
        fun({Type, Message, Domain, Length, Offset, Hex}) ->
            Input = input(Message),
            Expected = binary:decode_hex(Hex),
            Output = libdecaf:xof_turboshake(Type, Input, Length, Domain),
            Expected = binary:part(Output, Offset, byte_size(Expected)),
            Split = byte_size(Input) div 2,
            <<First:Split/binary, Last/binary>> = Input,
            State = libdecaf:xof_turboshake_init(Type, Domain),
            Updated = libdecaf:xof_turboshake_update(
                libdecaf:xof_turboshake_update(State, [First]), [Last]
            ),
            Output = libdecaf:xof_turboshake_final(Updated, Length),
            case Domain of
                16#1f -> Output = libdecaf:xof_turboshake(Type, Input, Length);
                _ -> ok
            end
        end,
        Vectors
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
