%%% % @format
-module(hash_compat_SUITE).
-moduledoc """
Compatibility hash wrappers, legacy state tuples, and deprecation documentation.
""".
-moduledoc #{copyright => "Andrew Bennett"}.

-export([
    all/0,
    deprecation_and_examples/1,
    fixed_hashes/1,
    invalid_arguments/1,
    shake/1
]).

all() ->
    [fixed_hashes, shake, invalid_arguments, deprecation_and_examples].

fixed_hashes(_) ->
    lists:foreach(
        fun({Module, Algorithms}) ->
            lists:foreach(
                fun({Algorithm, DefaultLength}) ->
                    lists:foreach(
                        fun(Message) ->
                            Expected = libdecaf:hash_final(
                                libdecaf:hash_update(libdecaf:hash_init(Algorithm), Message)
                            ),
                            DefaultLength = byte_size(Expected),
                            Expected = Module:hash(Algorithm, [Message]),
                            Expected = Module:hash(Algorithm, Message, DefaultLength),
                            Initial = {Algorithm, Native0} = Module:init(Algorithm),
                            true = is_reference(Native0),
                            Updated = {Algorithm, Native1} = Module:update(Initial, [Message]),
                            true = is_reference(Native1),
                            Expected = Module:final(Updated),
                            Expected = Module:final(Updated),
                            Expected = Module:final(Module:update(Initial, Message)),
                            Empty = libdecaf:hash_final(libdecaf:hash_init(Algorithm)),
                            Empty = Module:final(Initial),
                            lists:foreach(
                                fun(Length) ->
                                    Prefix = binary:part(Expected, 0, Length),
                                    Prefix = Module:hash(Algorithm, Message, Length),
                                    Prefix = Module:final(Updated, Length)
                                end,
                                [0, 1, DefaultLength - 1, DefaultLength]
                            ),
                            badarg(fun() -> Module:hash(Algorithm, Message, DefaultLength + 1) end),
                            badarg(fun() -> Module:final(Updated, DefaultLength + 1) end)
                        end,
                        [<<>>, <<"abc">>, binary:copy(<<42>>, 65537)]
                    )
                end,
                Algorithms
            )
        end,
        profiles()
    ).

shake(_) ->
    Module = libdecaf_sha3,
    lists:foreach(
        fun(Algorithm) ->
            Initial = {Algorithm, _} = Module:init(Algorithm),
            Updated = {Algorithm, _} = Module:update(Module:update(Initial, <<"a">>), [<<"bc">>]),
            lists:foreach(
                fun(Length) ->
                    Expected = libdecaf:xof(Algorithm, <<"abc">>, Length),
                    Expected = Module:hash(Algorithm, [<<"abc">>], Length),
                    Expected = Module:xof(Algorithm, <<"abc">>, Length),
                    Expected = Module:final(Updated, Length),
                    Expected = Module:final(Updated, Length),
                    Empty = libdecaf:xof(Algorithm, <<>>, Length),
                    Empty = Module:final(Initial, Length)
                end,
                [0, 1, 32, 65537]
            ),
            rejected(fun() -> Module:hash(Algorithm, <<"abc">>) end, [Algorithm, <<"abc">>]),
            rejected(fun() -> Module:final(Updated) end, [Updated])
        end,
        [shake128, shake256]
    ).

invalid_arguments(_) ->
    lists:foreach(
        fun({Module, [{Algorithm, _} | _]}) ->
            rejected(fun() -> Module:hash(unknown, <<>>) end, [unknown, <<>>]),
            rejected(fun() -> Module:hash(unknown, <<>>, 1) end, [unknown, <<>>, 1]),
            rejected(fun() -> Module:init(unknown) end, [unknown]),
            lists:foreach(
                fun(State) ->
                    rejected(fun() -> Module:update(State, <<>>) end, [State, <<>>]),
                    rejected(fun() -> Module:final(State) end, [State]),
                    rejected(fun() -> Module:final(State, 1) end, [State, 1])
                end,
                [make_ref(), {unknown, make_ref()}, {Algorithm}]
            ),
            badarg(fun() -> Module:update({Algorithm, make_ref()}, <<>>) end),
            badarg(fun() -> Module:final({Algorithm, make_ref()}) end),
            badarg(fun() -> Module:hash(Algorithm, [invalid_iodata]) end),
            badarg(fun() -> Module:hash(Algorithm, <<>>, -1) end)
        end,
        profiles()
    ),
    Module = libdecaf_sha3,
    rejected(fun() -> Module:xof(sha3_256, <<>>, 32) end, [sha3_256, <<>>, 32]),
    badarg(fun() -> Module:final({shake128, libdecaf_nif:hash_init(sha3_256)}, 32) end),
    badarg(fun() -> Module:final({sha3_256, libdecaf_nif:xof_init(shake128)}, 32) end).

deprecation_and_examples(_) ->
    lists:foreach(
        fun({Module, _}) ->
            {ok, {docs_v1, _, erlang, <<"text/markdown">>, ModuleDoc, Metadata, Entries}} = code:get_doc(Module),
            true = maps:is_key(deprecated, Metadata),
            [module] = proplists:get_value(deprecated, Module:module_info(attributes)),
            lists:foreach(
                fun
                    ({{function, _, _}, _, _, Doc, FunctionMetadata}) ->
                        true = maps:is_key(deprecated, FunctionMetadata),
                        true = is_binary(maps:get(<<"en">>, Doc));
                    (_) ->
                        ok
                end,
                Entries
            ),
            {match, [[Example]]} = re:run(maps:get(<<"en">>, ModuleDoc), <<"```erlang\\n(.*?)```">>, [
                global, dotall, {capture, [1], binary}
            ]),
            {ok, Tokens, _} = erl_scan:string(unicode:characters_to_list(Example)),
            {ok, Expressions} = erl_parse:parse_exprs(Tokens),
            {value, _, _} = erl_eval:exprs(Expressions, erl_eval:new_bindings())
        end,
        profiles()
    ).

profiles() ->
    [
        {libdecaf_keccak_sha3, [{keccak_224, 28}, {keccak_256, 32}, {keccak_384, 48}, {keccak_512, 64}]},
        {libdecaf_sha2, [{sha2_512, 64}]},
        {libdecaf_sha3, [{sha3_224, 28}, {sha3_256, 32}, {sha3_384, 48}, {sha3_512, 64}]}
    ].

rejected(Function, Arguments) ->
    try Function() of
        Value -> ct:fail({expected_legacy_badarg, Arguments, Value})
    catch
        error:{badarg, Arguments} -> ok
    end.

badarg(Function) ->
    try Function() of
        Value -> ct:fail({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.
