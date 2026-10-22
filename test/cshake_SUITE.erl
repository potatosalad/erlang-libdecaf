%%% % @format
-module(cshake_SUITE).
-moduledoc """
SP 800-185 cSHAKE examples, framing boundaries, and immutable-state regressions.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    immutable_states/1,
    invalid_arguments/1,
    large_customization/1,
    nist_vectors/1,
    reference_vectors/1,
    shake_equivalence/1
]).

all() ->
    [nist_vectors, reference_vectors, shake_equivalence, large_customization, immutable_states, invalid_arguments].

immutable_states(_) ->
    each(fun(Type, _) ->
        Initial = libdecaf:hash_xof_init(Type, <<"KMAC">>, <<"domain">>),
        true = is_reference(Initial),
        Empty = libdecaf:hash_xof(Type, <<>>, 200, <<"KMAC">>, <<"domain">>),
        First = libdecaf:hash_xof_update(Initial, <<"one">>),
        Second = libdecaf:hash_xof_update(Initial, <<"two">>),
        Empty = libdecaf:hash_xof_final(Initial, 200),
        <<>> = libdecaf:hash_xof_final(First, 0),
        One = libdecaf:hash_xof(Type, <<"one">>, 200, <<"KMAC">>, <<"domain">>),
        One = libdecaf:hash_xof_final(First, 200),
        One = libdecaf:hash_xof_final(First, 200),
        Two = libdecaf:hash_xof(Type, <<"two">>, 200, <<"KMAC">>, <<"domain">>),
        Two = libdecaf:hash_xof_final(Second, 200),
        true = One =/= Two
    end).

invalid_arguments(_) ->
    each(fun(Type, Shake) ->
        lists:foreach(fun badarg/1, [
            fun() -> libdecaf:hash_xof(Type, <<>>, -1, <<>>, <<>>) end,
            fun() -> libdecaf:hash_xof(Type, <<>>, 32, invalid, <<>>) end,
            fun() -> libdecaf:hash_xof(Type, <<>>, 32, <<>>, [256]) end,
            fun() -> libdecaf:hash_xof(Type, invalid, 32, <<>>, <<"domain">>) end,
            fun() -> libdecaf:hash_xof_init(Type, <<>>, invalid) end,
            fun() -> libdecaf:hash_xof_init(Type, [256], <<>>) end,
            fun() -> libdecaf:hash_xof(Shake, <<>>, 32, <<>>, <<>>) end,
            fun() -> libdecaf:hash_xof_init(Shake, <<>>, <<>>) end,
            fun() -> libdecaf:hash_init(Type) end
        ])
    end).

large_customization(Config) ->
    lists:foreach(
        fun
            ({Type, NameSpec = {repeat, _, _}, CustomSpec, MessageSpec, Hex}) ->
                Name = input(NameSpec),
                Custom = input(CustomSpec),
                Message = input(MessageSpec),
                Prefix = binary:decode_hex(Hex),
                Output = libdecaf:hash_xof(Type, Message, 131073, Name, Custom),
                Prefix = binary:part(Output, 0, byte_size(Prefix)),
                State = libdecaf:hash_xof_init(Type, [Name], [[], Custom]),
                true = is_reference(State),
                Updated = libdecaf:hash_xof_update(State, [Message]),
                Output = libdecaf:hash_xof_final(Updated, 131073),
                Output = libdecaf:hash_xof_final(Updated, 131073);
            (_) ->
                ok
        end,
        vectors(Config)
    ).

nist_vectors(_) ->
    %% https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
    Vectors = [
        {cshake128, 4, <<"C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5">>},
        {cshake128, 200, <<"C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B">>},
        {cshake256, 4, <<
            "D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1",
            "64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C"
        >>},
        {cshake256, 200, <<
            "07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917",
            "27F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB"
        >>}
    ],
    lists:foreach(
        fun({Type, Length, Hex}) ->
            Message = list_to_binary(lists:seq(0, Length - 1)),
            check(Type, <<>>, [<<"Email">>, 32, <<"Signature">>], Message, binary:decode_hex(Hex))
        end,
        Vectors
    ).

reference_vectors(Config) ->
    lists:foreach(
        fun({Type, Name, Custom, Message, Hex}) ->
            check(Type, input(Name), input(Custom), input(Message), binary:decode_hex(Hex))
        end,
        vectors(Config)
    ).

shake_equivalence(_) ->
    each(fun(Type, Shake) ->
        lists:foreach(
            fun(Message) ->
                State = libdecaf:hash_xof_update(libdecaf:hash_xof_init(Type), Message),
                Explicit = libdecaf:hash_xof_update(libdecaf:hash_xof_init(Type, [], [<<>>]), Message),
                lists:foreach(
                    fun(Length) ->
                        Expected = libdecaf:hash_xof(Shake, Message, Length),
                        Expected = libdecaf:hash_xof(Type, Message, Length),
                        Expected = libdecaf:hash_xof(Type, Message, Length, <<>>, []),
                        Expected = libdecaf:hash_xof_final(State, Length),
                        Expected = libdecaf:hash_xof_final(Explicit, Length)
                    end,
                    [0, 32, 169, 65537]
                )
            end,
            [<<>>, <<"abc">>, binary:copy(<<42>>, 65537)]
        )
    end).

badarg(Fun) ->
    try Fun() of
        Result -> ct:fail({expected_badarg, Result})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

check(Type, Name, Custom, Message, Expected) ->
    Length = byte_size(Expected),
    Expected = libdecaf:hash_xof(Type, Message, Length, Name, Custom),
    Split = byte_size(Message) div 2,
    <<First:Split/binary, Last/binary>> = Message,
    State = libdecaf:hash_xof_init(Type, Name, Custom),
    Updated = libdecaf:hash_xof_update(libdecaf:hash_xof_update(State, [First]), [Last]),
    Expected = libdecaf:hash_xof_final(Updated, Length),
    Expected = libdecaf:hash_xof_final(Updated, Length).

each(Fun) ->
    lists:foreach(fun({Type, Shake}) -> Fun(Type, Shake) end, [{cshake128, shake128}, {cshake256, shake256}]).

input({repeat, Byte, Length}) -> binary:copy(<<Byte>>, Length);
input(Hex) -> binary:decode_hex(Hex).

vectors(Config) ->
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), "vectors.config")),
    Vectors.
