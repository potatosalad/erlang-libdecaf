%%% % @format
-module(hash_api_SUITE).
-moduledoc """
Grouped native hash APIs, parameter contracts, and state isolation.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    cancellation/1,
    fixed_hashes/1,
    group_isolation/1,
    parameters/1,
    trapping/1,
    xofs/1
]).

all() ->
    [fixed_hashes, xofs, parameters, group_isolation, trapping, cancellation].

fixed_hashes(_) ->
    lists:foreach(
        fun({Group, Algorithms}) ->
            lists:foreach(
                fun(Algorithm) ->
                    lists:foreach(
                        fun(Message) ->
                            Expected = libdecaf:hash(Algorithm, Message),
                            Expected = call(Group, "", [Algorithm, Message]),
                            Initial = call(Group, "_init", [Algorithm]),
                            true = is_reference(Initial),
                            State = call(Group, "_update", [Initial, [Message]]),
                            Expected = call(Group, "_final", [State]),
                            Expected = call(Group, "_final", [State]),
                            Empty = libdecaf:hash(Algorithm, <<>>),
                            Empty = call(Group, "_final", [Initial]),
                            lists:foreach(
                                fun(Length) ->
                                    Prefix = binary:part(Expected, 0, Length),
                                    Prefix = call(Group, "", [Algorithm, [Message], Length]),
                                    Prefix = call(Group, "_final", [State, Length])
                                end,
                                [0, 1, byte_size(Expected)]
                            ),
                            badarg(fun() ->
                                call(Group, "_final", [State, byte_size(Expected) + 1])
                            end)
                        end,
                        [<<>>, <<"abc">>, binary:copy(<<42>>, 65537)]
                    )
                end,
                Algorithms
            )
        end,
        hash_groups()
    ).

group_isolation(_) ->
    Groups = hash_groups() ++ xof_groups(),
    lists:foreach(
        fun({Group, [Algorithm | _]}) ->
            State = call(Group, "_init", [Algorithm]),
            lists:foreach(
                fun
                    ({Other, _}) when Other =:= Group -> ok;
                    ({Other, Others}) ->
                        lists:foreach(
                            fun(WrongAlgorithm) ->
                                badarg(fun() -> call(Group, "_init", [WrongAlgorithm]) end)
                            end,
                            Others
                        ),
                        badarg(fun() -> call(Other, "_update", [State, <<>>]) end),
                        badarg(fun() -> call(Other, "_final", [State, 1]) end)
                end,
                Groups
            ),
            badarg(fun() -> call(Group, "_update", [make_ref(), <<>>]) end),
            badarg(fun() -> call(Group, "_final", [make_ref(), 1]) end)
        end,
        Groups
    ).

parameters(_) ->
    Message = binary:copy(<<16#A3>>, 65537),
    lists:foreach(
        fun(Algorithm) ->
            Expected = libdecaf:hash_xof(
                Algorithm, Message, 65537, <<"Function">>, <<"Customization">>
            ),
            Expected = libdecaf_nif:hash_xof_cshake(
                Algorithm, [Message], 65537, <<"Function">>, <<"Customization">>
            ),
            State = libdecaf_nif:hash_xof_cshake_init(
                Algorithm, <<"Function">>, <<"Customization">>
            ),
            Updated = libdecaf_nif:hash_xof_cshake_update(State, Message),
            Expected = libdecaf_nif:hash_xof_cshake_final(Updated, 65537),
            badarg(fun() -> libdecaf_nif:hash_xof_cshake_init(Algorithm, 31, <<>>) end)
        end,
        [cshake128, cshake256]
    ),
    lists:foreach(
        fun(Algorithm) ->
            Expected = libdecaf:hash_xof(Algorithm, Message, 65537, 127),
            Expected = libdecaf_nif:hash_xof_turboshake(Algorithm, Message, 65537, 127),
            State = libdecaf_nif:hash_xof_turboshake_init(Algorithm, 127),
            Updated = libdecaf_nif:hash_xof_turboshake_update(State, Message),
            Expected = libdecaf_nif:hash_xof_turboshake_final(Updated, 65537),
            lists:foreach(
                fun(Domain) ->
                    badarg(fun() -> libdecaf_nif:hash_xof_turboshake_init(Algorithm, Domain) end)
                end,
                [0, 128, <<31>>]
            )
        end,
        [turboshake128, turboshake256]
    ),
    lists:foreach(
        fun(Algorithm) ->
            Expected = libdecaf:hash_xof(Algorithm, Message, 65537, <<"Customization">>),
            Expected = libdecaf_nif:hash_xof_kt(Algorithm, Message, 65537, <<"Customization">>),
            State = libdecaf_nif:hash_xof_kt_init(Algorithm),
            Updated = libdecaf_nif:hash_xof_kt_update(State, Message),
            Expected = libdecaf_nif:hash_xof_kt_final(Updated, 65537, <<"Customization">>),
            Expected = libdecaf_nif:hash_xof_kt_final(Updated, 65537, <<"Customization">>),
            badarg(fun() -> libdecaf_nif:hash_xof_kt_final(Updated, 32, 31) end)
        end,
        [kt128, kt256]
    ).

xofs(_) ->
    lists:foreach(
        fun({Group, Algorithms}) ->
            lists:foreach(
                fun(Algorithm) ->
                    Initial = call(Group, "_init", [Algorithm]),
                    true = is_reference(Initial),
                    Message = binary:copy(<<42>>, 65537),
                    State = call(Group, "_update", [Initial, [<<"abc">>, Message]]),
                    lists:foreach(
                        fun(Length) ->
                            Expected = libdecaf:hash_xof(Algorithm, [<<"abc">>, Message], Length),
                            Expected = call(Group, "", [Algorithm, [<<"abc">>, Message], Length]),
                            Expected = call(Group, "_final", [State, Length]),
                            Expected = call(Group, "_final", [State, Length]),
                            Empty = libdecaf:hash_xof(Algorithm, <<>>, Length),
                            Empty = call(Group, "_final", [Initial, Length])
                        end,
                        [0, 32, 169, 65537]
                    )
                end,
                Algorithms
            )
        end,
        xof_groups()
    ).

trapping(_) ->
    Message = binary:copy(<<42>>, 1000001),
    lists:foreach(
        fun({Group, Algorithms}) ->
            Absorb = continuation(Group, "absorb"),
            Squeeze = continuation(Group, "squeeze"),
            lists:foreach(
                fun(Algorithm) ->
                    Expected = traced(
                        fun() -> call(Group, "", [Algorithm, Message, 1000001]) end,
                        [Absorb, Squeeze]
                    ),
                    State = call(Group, "_init", [Algorithm]),
                    Updated = traced(
                        fun() -> call(Group, "_update", [State, [Message]]) end, [Absorb]
                    ),
                    Expected = traced(
                        fun() -> call(Group, "_final", [Updated, 1000001]) end, [Squeeze]
                    ),
                    %% Exercise both sides of the per-call reduction budget.
                    lists:foreach(
                        fun(Length) ->
                            Input = binary:part(Message, 0, Length),
                            Whole = call(Group, "", [Algorithm, Input, 20001]),
                            <<First:10000/binary, Rest/binary>> = Input,
                            Split = call(Group, "_update", [State, First]),
                            Joined = call(Group, "_update", [Split, Rest]),
                            Whole = call(Group, "_final", [Joined, 20001]),
                            <<>> = call(Group, "_final", [Joined, 0])
                        end,
                        [19999, 20000, 20001, 40000, 40001]
                    ),
                    lists:foreach(
                        fun(Invalid) ->
                            badarg(fun() -> call(Group, "", [Algorithm, Invalid, 32]) end),
                            badarg(fun() -> call(Group, "_update", [State, Invalid]) end)
                        end,
                        [42, invalid, [256], [<<"abc">> | invalid]]
                    )
                end,
                Algorithms
            )
        end,
        xof_groups()
    ),
    C0 = traced(
        fun() -> libdecaf_nif:hash_xof_cshake_init(cshake128, Message, Message) end,
        [continuation(hash_xof_cshake, "absorb")]
    ),
    C1 = libdecaf_nif:hash_xof_cshake_update(C0, <<"abc">>),
    CExpected = libdecaf_nif:hash_xof_cshake(cshake128, <<"abc">>, 32, Message, Message),
    CExpected = libdecaf_nif:hash_xof_cshake_final(C1, 32),
    K0 = libdecaf_nif:hash_xof_kt_init(kt128),
    KExpected = libdecaf_nif:hash_xof_kt(kt128, <<>>, 1000001, Message),
    KExpected = traced(
        fun() -> libdecaf_nif:hash_xof_kt_final(K0, 1000001, Message) end,
        [continuation(hash_xof_kt, "absorb"), continuation(hash_xof_kt, "squeeze")]
    ),
    badarg(fun() -> libdecaf_nif:hash_xof_cshake(cshake128, 42, 32, <<>>, <<>>) end),
    badarg(fun() -> libdecaf_nif:hash_xof_kt(kt128, 42, 32, <<>>) end).

cancellation(_) ->
    Message = binary:copy(<<42>>, 8000001),
    lists:foreach(
        fun({Group, [Algorithm | _]}) ->
            State = call(Group, "_init", [Algorithm]),
            cancelled(
                fun() -> call(Group, "", [Algorithm, Message, 32]) end,
                continuation(Group, "absorb")
            ),
            cancelled(
                fun() -> call(Group, "_update", [State, Message]) end,
                continuation(Group, "absorb")
            ),
            cancelled(
                fun() -> call(Group, "_final", [State, 8000001]) end,
                continuation(Group, "squeeze")
            ),
            %% Cancelling work on a copy must leave the caller's state usable.
            Empty = call(Group, "", [Algorithm, <<>>, 32]),
            Empty = call(Group, "_final", [State, 32])
        end,
        xof_groups()
    ),
    cancelled(
        fun() -> libdecaf_nif:hash_xof_cshake_init(cshake128, Message, Message) end,
        continuation(hash_xof_cshake, "absorb")
    ),
    State = libdecaf_nif:hash_xof_kt_init(kt128),
    cancelled(
        fun() -> libdecaf_nif:hash_xof_kt_final(State, 32, Message) end,
        continuation(hash_xof_kt, "absorb")
    ).

continuation(Group, Phase) ->
    list_to_atom("libdecaf_nif_" ++ atom_to_list(Group) ++ "_" ++ Phase ++ "_continue").

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

badarg(Fun) ->
    try Fun() of
        Result -> ct:fail({expected_badarg, Result})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.

call(Group, Suffix, Args) ->
    apply(libdecaf_nif, list_to_atom(atom_to_list(Group) ++ Suffix), Args).

hash_groups() ->
    [
        {hash_keccak, [keccak_224, keccak_256, keccak_384, keccak_512]},
        {hash_sha2, [sha2_512]},
        {hash_sha3, [sha3_224, sha3_256, sha3_384, sha3_512]}
    ].

xof_groups() ->
    [
        {hash_xof_cshake, [cshake128, cshake256]},
        {hash_xof_keccak, [keccak_xof_128, keccak_xof_256]},
        {hash_xof_kt, [kt128, kt256]},
        {hash_xof_sha3, [shake128, shake256]},
        {hash_xof_turboshake, [turboshake128, turboshake256]}
    ].
