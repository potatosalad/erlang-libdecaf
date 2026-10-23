%%% % @format
-module(hash_api_SUITE).
-moduledoc """
Generic fixed-output hashes, grouped XOF APIs, and state isolation.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    cancellation/1,
    fixed_hash_cancellation/1,
    fixed_hash_trapping/1,
    fixed_hashes/1,
    group_isolation/1,
    parameters/1,
    public_api/1,
    trapping/1,
    xofs/1
]).

all() ->
    [
        fixed_hashes,
        fixed_hash_trapping,
        fixed_hash_cancellation,
        xofs,
        parameters,
        group_isolation,
        public_api,
        trapping,
        cancellation
    ].

fixed_hashes(_) ->
    lists:foreach(
        fun(Algorithm) ->
            lists:foreach(
                fun(Message) ->
                    Expected = libdecaf:hash(Algorithm, Message),
                    Expected = libdecaf_nif:hash(Algorithm, Message),
                    Initial = libdecaf_nif:hash_init(Algorithm),
                    true = is_reference(Initial),
                    State = libdecaf_nif:hash_update(Initial, [Message]),
                    Expected = libdecaf_nif:hash_final(State),
                    Expected = libdecaf_nif:hash_final(State),
                    Public = libdecaf:hash_update(libdecaf:hash_init(Algorithm), Message),
                    Expected = libdecaf:hash_final(Public),
                    Empty = libdecaf:hash(Algorithm, <<>>),
                    Empty = libdecaf_nif:hash_final(Initial),
                    lists:foreach(
                        fun(Length) ->
                            Prefix = binary:part(Expected, 0, Length),
                            Prefix = libdecaf_nif:hash(Algorithm, [Message], Length),
                            Prefix = libdecaf_nif:hash_final(State, Length),
                            Prefix = libdecaf:hash(Algorithm, Message, Length),
                            Prefix = libdecaf:hash_final(Public, Length)
                        end,
                        [0, 1, byte_size(Expected)]
                    ),
                    badarg(fun() -> libdecaf_nif:hash_final(State, byte_size(Expected) + 1) end)
                end,
                [<<>>, <<"abc">>, binary:copy(<<42>>, 65537)]
            )
        end,
        fixed_hash_algorithms()
    ).

fixed_hash_trapping(_) ->
    Message = binary:copy(<<42>>, 1000001),
    lists:foreach(
        fun(Algorithm) ->
            Initial = libdecaf_nif:hash_init(Algorithm),
            Expected = libdecaf_nif:hash(Algorithm, Message),
            Expected = traced(
                fun() -> libdecaf_nif:hash(Algorithm, [Message]) end,
                [libdecaf_nif_hash_3_continue]
            ),
            <<>> = traced(
                fun() -> libdecaf_nif:hash(Algorithm, Message, 0) end,
                [libdecaf_nif_hash_3_continue]
            ),
            Updated = traced(
                fun() -> libdecaf_nif:hash_update(Initial, [Message]) end,
                [libdecaf_nif_hash_update_2_continue]
            ),
            Expected = libdecaf_nif:hash_final(Updated),
            Expected = libdecaf_nif:hash_final(Updated),
            lists:foreach(
                fun(Length) ->
                    Input = binary:part(Message, 0, Length),
                    Whole = libdecaf_nif:hash(Algorithm, Input),
                    <<First:10000/binary, Rest/binary>> = Input,
                    Split = libdecaf_nif:hash_update(Initial, First),
                    Joined = libdecaf_nif:hash_update(Split, Rest),
                    Whole = libdecaf_nif:hash_final(Joined)
                end,
                [19999, 20000, 20001, 40000, 40001]
            ),
            Empty = libdecaf_nif:hash(Algorithm, <<>>),
            Empty = libdecaf_nif:hash_final(Initial)
        end,
        fixed_hash_algorithms()
    ).

fixed_hash_cancellation(_) ->
    Message = binary:copy(<<42>>, 8000001),
    lists:foreach(
        fun(Algorithm) ->
            Initial = libdecaf_nif:hash_init(Algorithm),
            cancelled(
                fun() -> libdecaf_nif:hash(Algorithm, Message) end,
                libdecaf_nif_hash_3_continue
            ),
            cancelled(
                fun() -> libdecaf_nif:hash_update(Initial, Message) end,
                libdecaf_nif_hash_update_2_continue
            ),
            Empty = libdecaf_nif:hash(Algorithm, <<>>),
            Empty = libdecaf_nif:hash_final(Initial),
            Updated = libdecaf_nif:hash_update(Initial, <<"abc">>),
            Expected = libdecaf_nif:hash(Algorithm, <<"abc">>),
            Expected = libdecaf_nif:hash_final(Updated)
        end,
        fixed_hash_algorithms()
    ).

group_isolation(_) ->
    Groups = [{hash, fixed_hash_algorithms()} | xof_groups()],
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
            Expected = libdecaf:hash_xof_cshake(
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
            Expected = libdecaf:hash_xof_turboshake(Algorithm, Message, 65537, 127),
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
            Expected = libdecaf:hash_xof_kt(Algorithm, Message, 65537, <<"Customization">>),
            Expected = libdecaf_nif:hash_xof_kt(Algorithm, Message, 65537, <<"Customization">>),
            State = libdecaf_nif:hash_xof_kt_init(Algorithm),
            Updated = libdecaf_nif:hash_xof_kt_update(State, Message),
            Expected = libdecaf_nif:hash_xof_kt_final(Updated, 65537, <<"Customization">>),
            Expected = libdecaf_nif:hash_xof_kt_final(Updated, 65537, <<"Customization">>),
            badarg(fun() -> libdecaf_nif:hash_xof_kt_final(Updated, 32, 31) end)
        end,
        [kt128, kt256]
    ).

public_api(_) ->
    lists:foreach(
        fun(Module) ->
            Exports = Module:module_info(exports),
            [] = [
                Export
             || Export = {Name, _} <- Exports,
                lists:member(Name, [hash_xof, hash_xof_init, hash_xof_update, hash_xof_final]) orelse
                    lists:any(
                        fun(Prefix) -> lists:prefix(Prefix, atom_to_list(Name)) end,
                        ["hash_sha2", "hash_sha3", "hash_keccak"]
                    )
            ],
            lists:foreach(
                fun(Export) -> true = lists:member(Export, Exports) end,
                [
                    {hash, 2},
                    {hash, 3},
                    {hash_init, 1},
                    {hash_update, 2},
                    {hash_final, 1},
                    {hash_final, 2}
                ]
            )
        end,
        [libdecaf, libdecaf_nif]
    ),
    Native = libdecaf_nif:module_info(exports),
    Public = libdecaf:module_info(exports),
    XOFExports = [
        Export
     || Export = {Name, _} <- Native,
        lists:prefix("hash_xof_", atom_to_list(Name))
    ],
    true = XOFExports =/= [],
    lists:foreach(fun(Export) -> true = lists:member(Export, Public) end, XOFExports),
    lists:foreach(
        fun({Group, Algorithms}) ->
            Init = list_to_atom(atom_to_list(Group) ++ "_init"),
            Update = list_to_atom(atom_to_list(Group) ++ "_update"),
            Final = list_to_atom(atom_to_list(Group) ++ "_final"),
            lists:foreach(
                fun(Algorithm) ->
                    Initial = apply(libdecaf, Init, [Algorithm]),
                    State = apply(libdecaf, Update, [Initial, [<<"a">>, <<"bc">>]]),
                    Expected = apply(libdecaf, Group, [Algorithm, <<"abc">>, 65537]),
                    Expected = apply(libdecaf, Final, [State, 65537]),
                    Expected = call(Group, "_final", [State, 65537]),
                    Empty = apply(libdecaf, Group, [Algorithm, <<>>, 32]),
                    Empty = apply(libdecaf, Final, [Initial, 32])
                end,
                Algorithms
            )
        end,
        xof_groups()
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
                            Expected = apply(libdecaf, Group, [
                                Algorithm, [<<"abc">>, Message], Length
                            ]),
                            Expected = call(Group, "", [Algorithm, [<<"abc">>, Message], Length]),
                            Expected = call(Group, "_final", [State, Length]),
                            Expected = call(Group, "_final", [State, Length]),
                            Empty = apply(libdecaf, Group, [Algorithm, <<>>, Length]),
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

fixed_hash_algorithms() ->
    [
        keccak_224,
        keccak_256,
        keccak_384,
        keccak_512,
        sha2_512,
        sha3_224,
        sha3_256,
        sha3_384,
        sha3_512
    ].

xof_groups() ->
    [
        {hash_xof_cshake, [cshake128, cshake256]},
        {hash_xof_keccak, [keccak_xof_128, keccak_xof_256]},
        {hash_xof_kt, [kt128, kt256]},
        {hash_xof_sha3, [shake128, shake256]},
        {hash_xof_turboshake, [turboshake128, turboshake256]}
    ].
