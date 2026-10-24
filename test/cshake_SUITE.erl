%%% % @format
-module(cshake_SUITE).
-compile(warn_missing_spec_all).
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

-type cshake_algorithm() :: cshake128 | cshake256.
-type input_spec() :: binary() | {repeat, byte(), non_neg_integer()}.
-type vector() :: {cshake_algorithm(), input_spec(), input_spec(), input_spec(), binary()}.

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [
        nist_vectors,
        reference_vectors,
        shake_equivalence,
        large_customization,
        immutable_states,
        invalid_arguments
    ].

-spec immutable_states(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
immutable_states(_) ->
    each(fun(Type, _) ->
        Initial = libdecaf:xof_init({Type, <<"KMAC">>, <<"domain">>}),
        true = is_reference(Initial),
        Empty = libdecaf:xof({Type, <<"KMAC">>, <<"domain">>}, <<>>, 200),
        First = libdecaf:xof_absorb(Initial, <<"one">>),
        Second = libdecaf:xof_absorb(Initial, <<"two">>),
        Empty = element(2, libdecaf:xof_squeeze(Initial, 200)),
        <<>> = element(2, libdecaf:xof_squeeze(First, 0)),
        One = libdecaf:xof({Type, <<"KMAC">>, <<"domain">>}, <<"one">>, 200),
        One = element(2, libdecaf:xof_squeeze(First, 200)),
        One = element(2, libdecaf:xof_squeeze(First, 200)),
        Two = libdecaf:xof({Type, <<"KMAC">>, <<"domain">>}, <<"two">>, 200),
        Two = element(2, libdecaf:xof_squeeze(Second, 200)),
        true = One =/= Two
    end),
    ok.

-spec invalid_arguments(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
invalid_arguments(_) ->
    each(fun(Type, Shake) ->
        lists:foreach(fun(Function) -> Function() end, [
            fun() -> libdecaf_ct:assert_badarg(libdecaf, xof, [{Type, <<>>, <<>>}, <<>>, -1]) end,
            fun() -> libdecaf_ct:assert_badarg(libdecaf, xof, [{Type, invalid, <<>>}, <<>>, 32]) end,
            fun() -> libdecaf_ct:assert_badarg(libdecaf, xof, [{Type, <<>>, [256]}, <<>>, 32]) end,
            fun() -> libdecaf_ct:assert_badarg(libdecaf, xof, [{Type, <<>>, <<"domain">>}, invalid, 32]) end,
            fun() -> libdecaf_ct:assert_badarg(libdecaf, xof_init, [{Type, <<>>, invalid}]) end,
            fun() -> libdecaf_ct:assert_badarg(libdecaf, xof_init, [{Type, [256], <<>>}]) end,
            fun() -> libdecaf_ct:assert_badarg(libdecaf, xof, [{Shake, <<>>, <<>>}, <<>>, 32]) end,
            fun() -> libdecaf_ct:assert_badarg(libdecaf, xof_init, [{Shake, <<>>, <<>>}]) end,
            fun() -> libdecaf_ct:assert_badarg(libdecaf, hash_init, [Type]) end
        ])
    end),
    ok.

-spec large_customization(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_customization(Config) ->
    lists:foreach(
        fun
            ({Type, NameSpec = {repeat, _, _}, CustomSpec, MessageSpec, Hex}) ->
                Name = input(NameSpec),
                Custom = input(CustomSpec),
                Message = input(MessageSpec),
                Prefix = binary:decode_hex(Hex),
                Output = libdecaf:xof({Type, Name, Custom}, Message, 131073),
                Prefix = binary:part(Output, 0, byte_size(Prefix)),
                State = libdecaf:xof_init({Type, [Name], [[], Custom]}),
                true = is_reference(State),
                Updated = libdecaf:xof_absorb(State, [Message]),
                Output = element(2, libdecaf:xof_squeeze(Updated, 131073)),
                Output = element(2, libdecaf:xof_squeeze(Updated, 131073));
            (_) ->
                ok
        end,
        vectors(Config)
    ),
    ok.

-spec nist_vectors(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
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
    ),
    ok.

-spec reference_vectors(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
reference_vectors(Config) ->
    lists:foreach(
        fun({Type, Name, Custom, Message, Hex}) ->
            check(Type, input(Name), input(Custom), input(Message), binary:decode_hex(Hex))
        end,
        vectors(Config)
    ),
    ok.

-spec shake_equivalence(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
shake_equivalence(_) ->
    each(fun(Type, Shake) ->
        lists:foreach(
            fun(Message) ->
                State = libdecaf:xof_absorb(libdecaf:xof_init(Type), Message),
                Explicit = libdecaf:xof_absorb(libdecaf:xof_init({Type, [], [<<>>]}), Message),
                lists:foreach(
                    fun(Length) ->
                        Expected = libdecaf:xof(Shake, Message, Length),
                        Expected = libdecaf:xof(Type, Message, Length),
                        Expected = libdecaf:xof({Type, <<>>, []}, Message, Length),
                        Expected = element(2, libdecaf:xof_squeeze(State, Length)),
                        Expected = element(2, libdecaf:xof_squeeze(Explicit, Length))
                    end,
                    [0, 32, 169, 65537]
                )
            end,
            [<<>>, <<"abc">>, binary:copy(<<42>>, 65537)]
        )
    end),
    ok.

-spec check(Type, Name, Customization, Message, Expected) -> Result when
    Type :: cshake_algorithm(),
    Name :: iodata(),
    Customization :: iodata(),
    Message :: binary(),
    Expected :: binary(),
    Result :: binary().
check(Type, Name, Custom, Message, Expected) ->
    Length = byte_size(Expected),
    Expected = libdecaf:xof({Type, Name, Custom}, Message, Length),
    Split = byte_size(Message) div 2,
    <<First:Split/binary, Last/binary>> = Message,
    State = libdecaf:xof_init({Type, Name, Custom}),
    Updated = libdecaf:xof_absorb(libdecaf:xof_absorb(State, [First]), [
        Last
    ]),
    Expected = element(2, libdecaf:xof_squeeze(Updated, Length)),
    Expected = element(2, libdecaf:xof_squeeze(Updated, Length)).

-spec each(Function) -> Result when Function :: fun((cshake_algorithm(), shake128 | shake256) -> term()), Result :: ok.
each(Fun) ->
    lists:foreach(fun({Type, Shake}) -> Fun(Type, Shake) end, [
        {cshake128, shake128}, {cshake256, shake256}
    ]).

-spec input(Input) -> Result when Input :: input_spec(), Result :: binary().
input({repeat, Byte, Length}) -> binary:copy(<<Byte>>, Length);
input(Hex) -> binary:decode_hex(Hex).

-spec vectors(Config) -> Result when Config :: ct_suite:ct_config(), Result :: [vector()].
vectors(Config) ->
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), "vectors.config")),
    Vectors.
