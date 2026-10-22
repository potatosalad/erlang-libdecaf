%%% % @format
-module(hash_api_SUITE).
-moduledoc """
Grouped native hash APIs, parameter contracts, and state isolation.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    fixed_hashes/1,
    group_isolation/1,
    parameters/1,
    xofs/1
]).

all() ->
    [fixed_hashes, xofs, parameters, group_isolation].

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
