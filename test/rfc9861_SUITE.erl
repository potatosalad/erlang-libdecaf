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
    turboshake_vectors/1
]).

all() ->
    [turboshake_vectors, domain_validation, immutable_states].

domain_validation(_) ->
    lists:foreach(
        fun(Type) ->
            lists:foreach(
                fun(Domain) ->
                    badarg(fun() -> libdecaf:hash_xof(Type, <<>>, 32, Domain) end),
                    badarg(fun() -> libdecaf:hash_xof_init(Type, Domain) end)
                end,
                [-1, 0, 128, 256, <<31>>, invalid]
            ),
            Expected = libdecaf:hash_xof(Type, <<"abc">>, 32),
            Expected = libdecaf:hash_xof(Type, <<"abc">>, 32, 16#1f)
        end,
        [turboshake128, turboshake256]
    ),
    badarg(fun() -> libdecaf:hash_xof(shake128, <<>>, 32, 31) end),
    badarg(fun() -> libdecaf:hash_xof_init(cshake128, 31) end).

immutable_states(_) ->
    lists:foreach(
        fun(Type) ->
            State = libdecaf:hash_xof_init(Type, 127),
            true = is_reference(State),
            Empty = libdecaf:hash_xof(Type, <<>>, 200, 127),
            One = libdecaf:hash_xof_update(State, <<"one">>),
            Two = libdecaf:hash_xof_update(State, <<"two">>),
            Empty = libdecaf:hash_xof_final(State, 200),
            Expected = libdecaf:hash_xof(Type, <<"one">>, 200, 127),
            Expected = libdecaf:hash_xof_final(One, 200),
            Expected = libdecaf:hash_xof_final(One, 200),
            Other = libdecaf:hash_xof(Type, <<"two">>, 200, 127),
            Other = libdecaf:hash_xof_final(Two, 200),
            <<>> = libdecaf:hash_xof_final(State, 0)
        end,
        [turboshake128, turboshake256]
    ).

turboshake_vectors(Config) ->
    lists:foreach(
        fun({Type, Message, Domain, Length, Offset, Hex}) ->
            Input = input(Message),
            Expected = binary:decode_hex(Hex),
            Output = libdecaf:hash_xof(Type, Input, Length, Domain),
            Expected = binary:part(Output, Offset, byte_size(Expected)),
            Split = byte_size(Input) div 2,
            <<First:Split/binary, Last/binary>> = Input,
            State = libdecaf:hash_xof_init(Type, Domain),
            Updated = libdecaf:hash_xof_update(libdecaf:hash_xof_update(State, [First]), [Last]),
            Output = libdecaf:hash_xof_final(Updated, Length),
            case Domain of
                16#1f -> Output = libdecaf:hash_xof(Type, Input, Length);
                _ -> ok
            end
        end,
        vectors("turboshake.config", Config)
    ).

badarg(Fun) ->
    try Fun() of
        Result -> ct:fail({expected_badarg, Result})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

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
