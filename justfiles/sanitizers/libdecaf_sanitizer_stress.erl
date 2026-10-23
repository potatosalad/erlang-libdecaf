%%% % @format
-module(libdecaf_sanitizer_stress).
-moduledoc """
Exercise native resource ownership, failure paths, and process cleanup under ASan.
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-export([
    run/1
]).

run(Count) ->
    asan = erlang:system_info(emu_type),
    batches(Count),
    erlang:garbage_collect(),
    io:format("[sanitizers] completed ~B cleanup iterations~n", [Count]).

batches(0) ->
    ok;
batches(Remaining) ->
    Size = min(100, Remaining),
    {Pid, Ref} = spawn_monitor(fun() ->
        keys(ed25519, 32, no_context),
        keys(ed448, 57, <<>>),
        Random = libdecaf_nif:spongerng_csprng_init_from_dev_urandom(),
        {_, <<>>} = libdecaf_nif:spongerng_csprng_next(Random, 0),
        lists:foreach(fun iteration/1, lists:seq(Remaining - Size + 1, Remaining)),
        erlang:garbage_collect()
    end),
    receive
        {'DOWN', Ref, process, Pid, normal} -> batches(Remaining - Size);
        {'DOWN', Ref, process, Pid, Reason} -> error({stress_worker_failed, Reason})
    after 60000 ->
        exit(Pid, kill),
        error(stress_worker_timeout)
    end.

iteration(Index) ->
    Input =
        case Index rem 100 of
            0 -> binary:copy(<<42>>, 65537);
            _ -> <<Index:64>>
        end,
    Expected = crypto:hash(sha3_256, Input),
    Expected = libdecaf_nif:hash(sha3_256, [Input]),
    Hash = libdecaf_nif:hash_update(libdecaf_nif:hash_init(sha3_256), Input),
    Expected = libdecaf_nif:hash_final(Hash),
    <<>> = libdecaf_nif:hash_final(libdecaf_nif:hash_update(libdecaf_nif:hash_init({sha3_256, 0}), Input)),
    {Family, Algorithm, Parameters} = lists:nth(Index rem length(xofs()) + 1, xofs()),
    Length =
        case Index rem 100 of
            0 -> 65537;
            _ -> 32
        end,

    Data =
        case Family of
            tuplehash -> [Input];
            _ -> Input
        end,
    Whole = libdecaf_nif:xof(list_to_tuple([Algorithm, Length | Parameters]), Data),
    Initial = libdecaf_nif:xof_init(list_to_tuple([Algorithm | Parameters])),
    State = libdecaf_nif:xof_absorb(Initial, [Input]),
    {Next, First} = libdecaf_nif:xof_squeeze(State, Length div 2),
    {_, Last} = libdecaf_nif:xof_squeeze(Next, Length - byte_size(First)),
    Whole = <<First/binary, Last/binary>>,
    {_, Whole} = libdecaf_nif:xof_squeeze(State, Length),
    badarg(fun() -> libdecaf_nif:xof_absorb(Next, <<>>) end),
    badarg(fun() -> libdecaf_nif:xof_absorb(State, [256]) end),
    badarg(fun() -> libdecaf_nif:xof_squeeze(Hash, 32) end),
    badarg(fun() -> libdecaf_nif:hash_update(State, <<>>) end),
    Keyed = libdecaf_nif:hash_init({kmac128, 32, <<"key">>, <<"custom">>}),
    _ = libdecaf_nif:hash_final(libdecaf_nif:hash_update(Keyed, Input)),
    {Curve, Bytes} =
        case Index rem 2 of
            0 -> {ristretto255, 32};
            _ -> {decaf448, 56}
        end,
    Base = call(Curve, "_base", []),
    Table = call(Curve, "_precompute", [Base]),
    Base = call(Curve, "_precomputed_scalarmul", [Table, <<1:(Bytes * 8)/little>>]),
    badarg(fun() -> call(Curve, "_precomputed_scalarmul", [Table, <<>>]) end),
    badarg(fun() -> call(Curve, "_precompute", [<<>>]) end),
    Random = libdecaf_nif:spongerng_csprng_init_from_buffer([Input], true),
    {_, Output} = libdecaf_nif:spongerng_csprng_next(Random, 32),
    32 = byte_size(Output),
    Stirred = libdecaf_nif:spongerng_csprng_stir(Random, [<<"seed">>]),
    {_, <<>>} = libdecaf_nif:spongerng_csprng_next(Stirred, 0),
    badarg(fun() -> libdecaf_nif:spongerng_csprng_next(State, 32) end).

keys(Curve, Bytes, Context) ->
    Secret = binary:copy(<<7>>, Bytes),
    Key = call(Curve, "_derive_keypair", [Secret]),
    Public = call(Curve, "_keypair_extract_public_key", [Key]),
    Signature = call(Curve, "_keypair_sign", [Key, <<"message">>, 0, Context]),
    true = call(Curve, "_verify", [Signature, Public, <<"message">>, 0, Context]),
    <<First, Rest/binary>> = Public,
    Mismatched = <<(First bxor 1), Rest/binary>>,
    fails(fun() -> call(Curve, "_sign", [Secret, Mismatched, <<"message">>, 0, Context]) end),
    fails(fun() -> call(Curve, "_sign_prehash", [Secret, Mismatched, <<"message">>, Context]) end),
    badarg(fun() -> call(Curve, "_derive_keypair", [<<>>]) end).

xofs() ->
    [
        {cshake, cshake128, [<<>>, <<"custom">>]},
        {cshake, cshake256, []},
        {hopmac, hopmac128, [<<"key">>, <<"custom">>]},
        {hopmac, hopmac256, [<<"key">>]},
        {keccak, keccakxof_128, []},
        {keccak, keccakxof_256, []},
        {kmac, kmacxof128, [<<"key">>]},
        {kmac, kmacxof256, [<<"key">>, <<"custom">>]},
        {kt, kt128, [<<"custom">>]},
        {kt, kt256, []},
        {parallelhash, parallelhashxof128, [1]},
        {parallelhash, parallelhashxof256, [8, <<"custom">>]},
        {sha3, shake128, []},
        {sha3, shake256, []},
        {tuplehash, tuplehashxof128, []},
        {tuplehash, tuplehashxof256, [<<"custom">>]},
        {turboshake, turboshake128, [127]},
        {turboshake, turboshake256, []}
    ].

call(Component, Suffix, Arguments) ->
    apply(libdecaf_nif, list_to_atom(atom_to_list(Component) ++ Suffix), Arguments).

badarg(Fun) ->
    try Fun() of
        Value -> error({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

fails(Fun) ->
    try Fun() of
        Value -> error({unexpected_success, Value})
    catch
        error:{error, _, _} -> ok
    end.
