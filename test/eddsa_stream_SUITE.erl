%%% % @format
-module(eddsa_stream_SUITE).
-compile(warn_missing_spec_all).
-include_lib("common_test/include/ct.hrl").
-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    empty_message/1,
    large_input/1,
    immutable_states/1,
    rejects_changes/1,
    invalid_arguments/1,
    curve_helpers/1,
    encoded_keys/1,
    resource_lifetimes/1,
    interrupted_updates/1
]).

-type prehash_algorithm() :: ed25519ph | ed448ph.
-type keypair() :: libdecaf_nif:ed25519_keypair() | libdecaf_nif:ed448_keypair().
-type stream_state() ::
    libdecaf_nif:ed25519ph_sign_state()
    | libdecaf_nif:ed25519ph_verify_state()
    | libdecaf_nif:ed448ph_sign_state()
    | libdecaf_nif:ed448ph_verify_state().

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [
        empty_message,
        large_input,
        immutable_states,
        rejects_changes,
        invalid_arguments,
        curve_helpers,
        encoded_keys,
        resource_lifetimes,
        interrupted_updates
    ].
-spec init_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    Config.
-spec end_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
end_per_suite(_) -> ok.

-spec keys(Algorithm) -> Result when Algorithm :: prehash_algorithm(), Result :: {keypair(), binary()}.
keys(ed25519ph) -> keys(libdecaf_curve25519, 32);
keys(ed448ph) -> keys(libdecaf_curve448, 57).
-spec keys(Curve, Bytes) -> Result when
    Curve :: libdecaf_curve25519 | libdecaf_curve448, Bytes :: 32 | 57, Result :: {keypair(), binary()}.
keys(Curve, Bytes) ->
    Key = Curve:keypair_derive(binary:copy(<<7>>, Bytes)),
    {Key, Curve:keypair_extract_public_key(Key)}.

-spec one_shot(Algorithm, Message, Key, Context) -> Result when
    Algorithm :: prehash_algorithm(), Message :: binary(), Key :: keypair(), Context :: binary(), Result :: binary().
one_shot(ed25519ph, Message, Key, Context) -> libdecaf_curve25519:ed25519ph_keypair_sign(Message, Key, Context);
one_shot(ed448ph, Message, Key, Context) -> libdecaf_curve448:ed448ph_keypair_sign(Message, Key, Context).

-spec each(Function) -> Result when Function :: fun((prehash_algorithm()) -> term()), Result :: ok.
each(F) -> lists:foreach(F, [ed25519ph, ed448ph]).

-spec empty_message(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
empty_message(_) ->
    each(fun(A) ->
        {Key, Public} = keys(A),
        S = nif(A, keypair_sign_init, [Key]),
        Signature = one_shot(A, <<>>, Key, <<>>),
        Signature = nif(A, sign_final, [S]),
        Signature = nif(A, sign_final, [nif(A, sign_update, [S, []])]),
        true = nif(A, verify_final, [nif(A, verify_init, [Signature, Public])])
    end),
    ok.

-spec large_input(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input(_) ->
    each(fun(A) ->
        {Key, Public} = keys(A),
        Chunks = [binary:copy(<<42>>, 20001), [<<1>>, binary:copy(<<3>>, 17013)], <<"tail">>],
        Message = iolist_to_binary(Chunks),
        Context = binary:copy(<<9>>, 255),
        Expected = one_shot(A, Message, Key, Context),
        S = lists:foldl(
            fun(Chunk, State) -> nif(A, sign_update, [State, Chunk]) end,
            nif(A, keypair_sign_init, [Key, Context]),
            Chunks
        ),
        Expected = nif(A, sign_final, [S]),
        V = lists:foldl(
            fun(Chunk, State) -> nif(A, verify_update, [State, Chunk]) end,
            nif(A, verify_init, [Expected, Public, Context]),
            Chunks
        ),
        true = nif(A, verify_final, [V])
    end),
    ok.

-spec immutable_states(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
immutable_states(_) ->
    each(fun(A) ->
        {Key, Public} = keys(A),
        S0 = nif(A, keypair_sign_init, [Key]),
        S1 = nif(A, sign_update, [S0, <<"one">>]),
        S2 = nif(A, sign_update, [S0, <<"two">>]),
        Empty = one_shot(A, <<>>, Key, <<>>),
        Empty = nif(A, sign_final, [S0]),
        One = one_shot(A, <<"one">>, Key, <<>>),
        One = nif(A, sign_final, [S1]),
        Two = one_shot(A, <<"two">>, Key, <<>>),
        Two = nif(A, sign_final, [S2]),
        V0 = nif(A, verify_init, [One, Public]),
        false = nif(A, verify_final, [V0]),
        V1 = nif(A, verify_update, [V0, <<"one">>]),
        true = nif(A, verify_final, [V1]),
        true = nif(A, verify_final, [V1]),
        Parent = self(),
        {Pid, Ref} = spawn_monitor(fun() -> Parent ! {self(), nif(A, sign_final, [S1])} end),
        receive
            {Pid, One} -> ok
        after 5000 -> ct:fail(stream_timeout)
        end,
        receive
            {'DOWN', Ref, process, Pid, normal} -> ok
        after 5000 -> ct:fail(stream_process)
        end
    end),
    ok.

-spec rejects_changes(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
rejects_changes(_) ->
    each(fun(A) ->
        {Key, Public} = keys(A),
        Signature = one_shot(A, <<"message">>, Key, <<"context">>),
        V0 = nif(A, verify_init, [Signature, Public, <<"context">>]),
        false = nif(A, verify_final, [nif(A, verify_update, [V0, <<"changed">>])]),
        V1 = nif(A, verify_init, [Signature, Public, <<"changed">>]),
        false = nif(A, verify_final, [nif(A, verify_update, [V1, <<"message">>])]),
        <<First, Rest/binary>> = Signature,
        Altered = <<(First bxor 1), Rest/binary>>,
        V2 = nif(A, verify_init, [Altered, Public, <<"context">>]),
        false = nif(A, verify_final, [nif(A, verify_update, [V2, <<"message">>])])
    end),
    ok.

-spec invalid_arguments(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
invalid_arguments(_) ->
    each(fun(A) ->
        Other =
            case A of
                ed25519ph -> ed448ph;
                ed448ph -> ed25519ph
            end,
        {Key, Public} = keys(A),
        {OtherKey, _} = keys(Other),
        S = nif(A, keypair_sign_init, [Key]),
        Signature = nif(A, sign_final, [S]),
        V = nif(A, verify_init, [Signature, Public]),
        OtherS = nif(Other, keypair_sign_init, [OtherKey]),
        Hash = libdecaf_nif:hash_init(sha2_512),
        XOF = libdecaf_nif:xof_init(shake256),
        lists:foreach(fun badarg/1, [
            fun() -> nif(A, keypair_sign_init, [OtherKey]) end,
            fun() -> nif(A, keypair_sign_init, [make_ref()]) end,
            fun() -> nif(A, keypair_sign_init, [Key, binary:copy(<<0>>, 256)]) end,
            fun() -> nif(A, keypair_sign_init, [Key, no_context]) end,
            fun() -> nif(A, sign_init, [Key]) end,
            fun() -> nif(A, sign_init, [<<>>]) end,
            fun() -> nif(A, verify_init, [<<>>, Public]) end,
            fun() -> nif(A, verify_init, [Signature, <<>>]) end,
            fun() -> nif(A, verify_init, [Signature, Public, binary:copy(<<0>>, 256)]) end,
            fun() -> nif(A, verify_init, [Signature, Public, no_context]) end,
            fun() -> nif(A, sign_update, [S, [256]]) end,
            fun() -> nif(A, verify_update, [V, [256]]) end,
            fun() -> nif(A, sign_final, [not_a_state]) end,
            fun() -> nif(A, sign_final, [V]) end,
            fun() -> nif(A, sign_update, [V, <<>>]) end,
            fun() -> nif(A, verify_update, [S, <<>>]) end,
            fun() -> nif(A, verify_final, [S]) end,
            fun() -> nif(A, sign_update, [OtherS, <<>>]) end,
            fun() -> nif(A, sign_final, [OtherS]) end,
            fun() -> nif(A, sign_update, [Hash, <<>>]) end,
            fun() -> nif(A, verify_update, [XOF, <<>>]) end,
            fun() -> libdecaf_nif:hash_update(S, <<>>) end,
            fun() -> libdecaf_nif:xof_absorb(V, <<>>) end
        ])
    end),
    ok.

-spec curve_helpers(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
curve_helpers(_) ->
    {K255, P255} = keys(ed25519ph),
    S255 = libdecaf_curve25519:ed25519ph_sign_update(libdecaf_curve25519:ed25519ph_keypair_sign_init(K255), <<"abc">>),
    Sig255 = libdecaf_curve25519:ed25519ph_sign_final(S255),
    V255 = libdecaf_curve25519:ed25519ph_verify_update(
        libdecaf_curve25519:ed25519ph_verify_init(Sig255, P255), <<"abc">>
    ),
    true = libdecaf_curve25519:ed25519ph_verify_final(V255),
    {K448, P448} = keys(ed448ph),
    S448 = libdecaf_curve448:ed448ph_sign_update(libdecaf_curve448:ed448ph_keypair_sign_init(K448, <<"c">>), <<"abc">>),
    Sig448 = libdecaf_curve448:ed448ph_sign_final(S448),
    V448 = libdecaf_curve448:ed448ph_verify_update(
        libdecaf_curve448:ed448ph_verify_init(Sig448, P448, <<"c">>), <<"abc">>
    ),
    true = libdecaf_curve448:ed448ph_verify_final(V448),
    ok.

-spec badarg(Function) -> Result when Function :: fun(() -> term()), Result :: ok.
badarg(F) ->
    try F() of
        Value -> ct:fail({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

-spec encoded_keys(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
encoded_keys(_) ->
    each(fun(A) ->
        {Curve, Bytes} = curve(A),
        Seed = binary:copy(<<7>>, Bytes),
        {Public, Encoded} = Curve:eddsa_keypair(Seed),
        Message = <<"encoded signing key">>,
        {Key, Public} = keys(A),
        lists:foreach(
            fun(Context) ->
                S0 = nif(A, sign_init, [Encoded, Context]),
                S1 = nif(A, sign_update, [S0, [Message]]),
                Expected = one_shot(A, Message, Key, Context),
                Expected = nif(A, sign_final, [S1]),
                Init = list_to_existing_atom(atom_to_list(A) ++ "_sign_init"),
                CurveState = apply(Curve, Init, [Encoded, Context]),
                Expected = nif(A, sign_final, [nif(A, sign_update, [CurveState, Message])])
            end,
            [<<>>, <<"context">>, binary:copy(<<1>>, 255)]
        ),
        Empty = one_shot(A, <<>>, Key, <<>>),
        Empty = nif(A, sign_final, [nif(A, sign_init, [Encoded])]),
        badarg(fun() -> nif(A, sign_init, [Encoded, no_context]) end),
        badarg(fun() -> nif(A, sign_init, [Encoded, binary:copy(<<0>>, 256)]) end),
        badarg(fun() -> nif(A, keypair_sign_init, [Encoded]) end),
        ChangedPublic = Curve:eddsa_secret_to_pk(binary:copy(<<8>>, Bytes)),
        try nif(A, sign_init, [<<Seed/binary, ChangedPublic/binary>>]) of
            _ -> ct:fail(mismatched_keypair_accepted)
        catch
            error:{error, _, _} -> ok
        end
    end),
    ok.

-spec resource_lifetimes(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
resource_lifetimes(_) ->
    each(fun(A) ->
        Parent = self(),
        {Pid, Ref} = spawn_monitor(fun() ->
            {Key, Public} = keys(A),
            Context = <<"retained context">>,
            Signature = one_shot(A, <<"message">>, Key, Context),
            S = nif(A, keypair_sign_init, [Key, Context]),
            V = nif(A, verify_init, [Signature, Public, Context]),
            {Curve, Bytes} = curve(A),
            {_, Encoded} = Curve:eddsa_keypair(binary:copy(<<7>>, Bytes)),
            EncodedS = nif(A, sign_init, [Encoded, Context]),
            Parent ! {self(), S, V, EncodedS, Signature}
        end),
        receive
            {Pid, S, V, EncodedS, Signature} ->
                receive
                    {'DOWN', Ref, process, Pid, normal} -> ok
                after 5000 -> ct:fail(worker_timeout)
                end,
                erlang:garbage_collect(),
                Signature = nif(A, sign_final, [nif(A, sign_update, [S, <<"message">>])]),
                Signature = nif(A, sign_final, [nif(A, sign_update, [EncodedS, <<"message">>])]),
                true = nif(A, verify_final, [nif(A, verify_update, [V, <<"message">>])])
        after 5000 -> ct:fail(state_timeout)
        end
    end),
    ok.

-spec interrupted_updates(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
interrupted_updates(_) ->
    Input = binary:copy(<<42>>, 8 * 1024 * 1024),
    each(fun(A) ->
        {Key, Public} = keys(A),
        S = nif(A, keypair_sign_init, [Key]),
        Signature = nif(A, sign_final, [S]),
        V = nif(A, verify_init, [Signature, Public]),
        lists:foreach(
            fun({Operation, State}) ->
                lists:foreach(
                    fun(_) ->
                        Parent = self(),
                        {Pid, Ref} = spawn_monitor(fun() ->
                            Parent ! {self(), updating},
                            repeat_updates(A, Operation, State, Input)
                        end),
                        receive
                            {Pid, updating} -> ok
                        after 5000 -> ct:fail(update_timeout)
                        end,
                        receive
                        after 1 -> ok
                        end,
                        exit(Pid, kill),
                        receive
                            {'DOWN', Ref, process, Pid, killed} -> ok
                        after 5000 -> ct:fail(kill_timeout)
                        end
                    end,
                    lists:seq(1, 8)
                )
            end,
            [{sign_update, S}, {verify_update, V}]
        ),
        % Cancelled updates operated on private copies of the published states.
        Signature = nif(A, sign_final, [S]),
        true = nif(A, verify_final, [V])
    end),
    erlang:garbage_collect(),
    ok.

-spec repeat_updates(Algorithm, Operation, State, Input) -> Result when
    Algorithm :: prehash_algorithm(),
    Operation :: sign_update | verify_update,
    State :: stream_state(),
    Input :: binary(),
    Result :: no_return().
repeat_updates(A, Operation, State, Input) ->
    _ = nif(A, Operation, [State, Input]),
    repeat_updates(A, Operation, State, Input).

-spec curve(Algorithm) -> Result when
    Algorithm :: prehash_algorithm(), Result :: {libdecaf_curve25519 | libdecaf_curve448, 32 | 57}.
curve(ed25519ph) -> {libdecaf_curve25519, 32};
curve(ed448ph) -> {libdecaf_curve448, 57}.

-spec nif(Algorithm, Operation, Arguments) -> Result when
    Algorithm :: prehash_algorithm(), Operation :: atom(), Arguments :: [term()], Result :: dynamic().
nif(Algorithm, Operation, Arguments) ->
    Function = list_to_existing_atom(atom_to_list(Algorithm) ++ "_" ++ atom_to_list(Operation)),
    apply(libdecaf_nif, Function, Arguments).
