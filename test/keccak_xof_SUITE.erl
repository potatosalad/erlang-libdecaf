%%% % @format
-module(keccak_xof_SUITE).
-moduledoc """
Original Keccak XOF vectors and incremental API regressions.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    known_answers/1,
    large_input_and_output/1,
    immutable_states/1,
    invalid_arguments/1
]).

all() ->
    [known_answers, large_input_and_output, immutable_states, invalid_arguments].

known_answers(Config) ->
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), "vectors.config")),
    lists:foreach(
        fun({Type, Message, Hex}) ->
            Input = input(Message),
            Expected = binary:decode_hex(Hex),
            Expected = libdecaf:xof_keccak(Type, Input, byte_size(Expected)),
            Split = byte_size(Input) div 2,
            <<First:Split/binary, Last/binary>> = Input,
            State = libdecaf:xof_keccak_update(libdecaf:xof_keccak_init(Type), [
                First, [Last]
            ]),
            Expected = libdecaf:xof_keccak_final(State, byte_size(Expected)),
            Expected = libdecaf:xof_keccak_final(State, byte_size(Expected)),
            lists:foreach(
                fun(Length) ->
                    Prefix = binary:part(Expected, 0, Length),
                    Prefix = libdecaf:xof_keccak_final(State, Length)
                end,
                [0, 1, 32, 136, 168, 169]
            )
        end,
        Vectors
    ).

large_input_and_output(_) ->
    each(fun(Type) ->
        Chunks = [binary:copy(<<0, 1, 2, 3>>, 65537), [<<"tail">>]],
        Expected = libdecaf:xof_keccak(Type, Chunks, 131073),
        State = libdecaf:xof_keccak_init(Type),
        Updated = lists:foldl(
            fun(Chunk, Acc) -> libdecaf:xof_keccak_update(Acc, Chunk) end, State, Chunks
        ),
        Expected = libdecaf:xof_keccak_final(Updated, 131073),
        Expected = libdecaf:xof_keccak_final(Updated, 131073)
    end).

immutable_states(_) ->
    each(fun(Type) ->
        Initial = libdecaf:xof_keccak_init(Type),
        true = is_reference(Initial),
        Empty = libdecaf:xof_keccak(Type, <<>>, 200),
        First = libdecaf:xof_keccak_update(Initial, <<"abc">>),
        Second = libdecaf:xof_keccak_update(Initial, <<"def">>),
        Empty = libdecaf:xof_keccak_final(Initial, 200),
        <<>> = libdecaf:xof_keccak_final(First, 0),
        Abc = libdecaf:xof_keccak(Type, <<"abc">>, 200),
        Abc = libdecaf:xof_keccak_final(First, 200),
        Def = libdecaf:xof_keccak(Type, <<"def">>, 200),
        Def = libdecaf:xof_keccak_final(Second, 200),
        Abcd = libdecaf:xof_keccak(Type, <<"abcd">>, 200),
        Abcd = libdecaf:xof_keccak_final(libdecaf:xof_keccak_update(First, <<"d">>), 200)
    end).

invalid_arguments(_) ->
    each(fun(Type) ->
        State = libdecaf:xof_keccak_init(Type),
        badarg(fun() -> libdecaf:hash_init(Type) end),
        badarg(fun() -> libdecaf:xof_keccak(Type, <<>>, -1) end),
        badarg(fun() -> libdecaf:xof_keccak_final(State, -1) end),
        badarg(fun() -> libdecaf:hash_update(State, <<>>) end)
    end).

each(Fun) ->
    lists:foreach(Fun, [keccak_xof_128, keccak_xof_256]).

input(empty) -> <<>>;
input(abc) -> <<"abc">>;
input({zeroes, Length}) -> binary:copy(<<0>>, Length).

badarg(Fun) ->
    try Fun() of
        Result -> ct:fail({expected_badarg, Result})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.
