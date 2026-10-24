%%% % @format
-module(keccak_xof_SUITE).
-compile(warn_missing_spec_all).
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

-type input_spec() :: empty | abc | {zeroes, non_neg_integer()}.

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [known_answers, large_input_and_output, immutable_states, invalid_arguments].

-spec known_answers(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
known_answers(Config) ->
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), "vectors.config")),
    lists:foreach(
        fun({Type, Message, Hex}) ->
            Input = input(Message),
            Expected = binary:decode_hex(Hex),
            Expected = libdecaf:xof(Type, Input, byte_size(Expected)),
            Split = byte_size(Input) div 2,
            <<First:Split/binary, Last/binary>> = Input,
            State = libdecaf:xof_absorb(libdecaf:xof_init(Type), [
                First, [Last]
            ]),
            Expected = element(2, libdecaf:xof_squeeze(State, byte_size(Expected))),
            Expected = element(2, libdecaf:xof_squeeze(State, byte_size(Expected))),
            lists:foreach(
                fun(Length) ->
                    Prefix = binary:part(Expected, 0, Length),
                    Prefix = element(2, libdecaf:xof_squeeze(State, Length))
                end,
                [0, 1, 32, 136, 168, 169]
            )
        end,
        Vectors
    ),
    ok.

-spec large_input_and_output(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_and_output(_) ->
    each(fun(Type) ->
        Chunks = [binary:copy(<<0, 1, 2, 3>>, 65537), [<<"tail">>]],
        Expected = libdecaf:xof(Type, Chunks, 131073),
        State = libdecaf:xof_init(Type),
        Updated = lists:foldl(
            fun(Chunk, Acc) -> libdecaf:xof_absorb(Acc, Chunk) end, State, Chunks
        ),
        Expected = element(2, libdecaf:xof_squeeze(Updated, 131073)),
        Expected = element(2, libdecaf:xof_squeeze(Updated, 131073))
    end),
    ok.

-spec immutable_states(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
immutable_states(_) ->
    each(fun(Type) ->
        Initial = libdecaf:xof_init(Type),
        true = is_reference(Initial),
        Empty = libdecaf:xof(Type, <<>>, 200),
        First = libdecaf:xof_absorb(Initial, <<"abc">>),
        Second = libdecaf:xof_absorb(Initial, <<"def">>),
        Empty = element(2, libdecaf:xof_squeeze(Initial, 200)),
        <<>> = element(2, libdecaf:xof_squeeze(First, 0)),
        Abc = libdecaf:xof(Type, <<"abc">>, 200),
        Abc = element(2, libdecaf:xof_squeeze(First, 200)),
        Def = libdecaf:xof(Type, <<"def">>, 200),
        Def = element(2, libdecaf:xof_squeeze(Second, 200)),
        Abcd = libdecaf:xof(Type, <<"abcd">>, 200),
        Abcd = element(2, libdecaf:xof_squeeze(libdecaf:xof_absorb(First, <<"d">>), 200))
    end),
    ok.

-spec invalid_arguments(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
invalid_arguments(_) ->
    each(fun(Type) ->
        State = libdecaf:xof_init(Type),
        libdecaf_ct:assert_badarg(libdecaf, hash_init, [Type]),
        libdecaf_ct:assert_badarg(libdecaf, xof, [Type, <<>>, -1]),
        libdecaf_ct:assert_badarg(libdecaf, xof_squeeze, [State, -1]),
        libdecaf_ct:assert_badarg(libdecaf, hash_update, [State, <<>>])
    end),
    ok.

-spec each(Function) -> Result when Function :: fun((keccakxof_128 | keccakxof_256) -> term()), Result :: ok.
each(Fun) ->
    lists:foreach(Fun, [keccakxof_128, keccakxof_256]).

-spec input(Input) -> Result when Input :: input_spec(), Result :: binary().
input(empty) -> <<>>;
input(abc) -> <<"abc">>;
input({zeroes, Length}) -> binary:copy(<<0>>, Length).
