%%% % @format
-module(tuak_SUITE).
-moduledoc """
Exercise every TUAK test set in TS 35.232 and TS 35.233 Release 19 through the NIF.
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    vector_1/1,
    vector_2/1,
    vector_3/1,
    vector_4/1,
    vector_5/1,
    vector_6/1,
    defaults/1,
    invalid_arguments/1,
    output_domains/1,
    concurrent/1
]).

all() ->
    [
        {group, implementers_mac},
        {group, implementers_derive},
        {group, conformance},
        defaults,
        invalid_arguments,
        output_domains,
        concurrent
    ].

groups() ->
    [
        {Name, [parallel], [vector_1, vector_2, vector_3, vector_4, vector_5, vector_6]}
     || Name <- [implementers_mac, implementers_derive, conformance]
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    {module, libdecaf_nif} = code:ensure_loaded(libdecaf_nif),
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), "vectors.config")),
    [{vectors, Vectors} | Config].

end_per_suite(_) -> ok.
end_per_group(_, _) -> ok.

init_per_group(Name, Config) ->
    [{cases, proplists:get_value(Name, ?config(vectors, Config))} | Config].

vector_1(Config) -> vector(1, Config).
vector_2(Config) -> vector(2, Config).
vector_3(Config) -> vector(3, Config).
vector_4(Config) -> vector(4, Config).
vector_5(Config) -> vector(5, Config).
vector_6(Config) -> vector(6, Config).

vector(Index, Config) ->
    V = lists:nth(Index, ?config(cases, Config)),
    Key = hex(key, V),
    TOP = hex(top, V),
    TOPc = hex(topc, V),
    RAND = hex(rand, V),
    Iterations = maps:with([iterations], V),
    TOPc = call(topc, [Key, TOP, Iterations]),
    case maps:is_key(f1, V) of
        true ->
            SQN = hex(sqn, V),
            AMF = hex(amf, V),
            MACOptions = maps:with([mac_length, iterations], V),
            MAC_A = hex(f1, V),
            MAC_S = hex(f1_star, V),
            MAC_A = call(f1, [Key, TOPc, RAND, SQN, AMF, MACOptions]),
            MAC_S = call(f1_star, [Key, TOPc, RAND, SQN, AMF, MACOptions]);
        false ->
            ok
    end,
    case maps:is_key(f2, V) of
        true ->
            Options = maps:with([res_length, ck_length, ik_length, iterations], V),
            Expected = {hex(f2, V), hex(f3, V), hex(f4, V), hex(f5, V)},
            Expected = call(f2345, [Key, TOPc, RAND, Options]),
            lists:foreach(
                fun({Function, Output}) ->
                    Output = call(Function, [Key, TOPc, RAND, Options])
                end,
                lists:zip([f2, f3, f4, f5], tuple_to_list(Expected))
            ),
            AKStar = hex(f5_star, V),
            AKStar = call(f5_star, [Key, TOPc, RAND, Iterations]);
        false ->
            ok
    end,
    ok.

defaults(_) ->
    {Key, TOP, RAND, SQN, AMF} = inputs(),
    TOPc = call(topc, [Key, TOP]),
    TOPc = call(topc, [Key, TOP, #{}]),
    TOPc = call(topc, [Key, TOP, #{iterations => 1}]),
    lists:foreach(
        fun(Function) ->
            Expected = call(Function, [Key, TOPc, RAND, SQN, AMF]),
            Expected = call(Function, [Key, TOPc, RAND, SQN, AMF, #{mac_length => 8, iterations => 1}])
        end,
        [f1, f1_star]
    ),
    Options = #{res_length => 8, ck_length => 16, ik_length => 16, iterations => 1},
    lists:foreach(
        fun(Function) ->
            Expected = call(Function, [Key, TOPc, RAND]),
            Expected = call(Function, [Key, TOPc, RAND, Options])
        end,
        [f2, f3, f4, f5, f2345]
    ),
    Star = call(f5_star, [Key, TOPc, RAND]),
    Star = call(f5_star, [Key, TOPc, RAND, #{iterations => 1}]),
    ok.

invalid_arguments(_) ->
    {Key, TOP, RAND, SQN, AMF} = inputs(),
    TOPc = call(topc, [Key, TOP]),
    Calls = [
        {topc, [Key, TOP]},
        {f1, [Key, TOPc, RAND, SQN, AMF]},
        {f1_star, [Key, TOPc, RAND, SQN, AMF]}
        | [{F, [Key, TOPc, RAND]} || F <- [f2, f3, f4, f5, f2345, f5_star]]
    ],
    lists:foreach(
        fun({Function, Args}) ->
            lists:foreach(
                fun(Index) ->
                    lists:foreach(
                        fun(Bad) ->
                            badarg(fun() -> call(Function, replace(Index, Bad, Args)) end)
                        end,
                        [<<>>, <<0>>, [0], undefined, binary:copy(<<0>>, 33)]
                    )
                end,
                lists:seq(1, length(Args))
            ),
            lists:foreach(
                fun(Options) ->
                    badarg(fun() -> call(Function, Args ++ [Options]) end)
                end,
                [
                    [],
                    undefined,
                    #{iterations => 0},
                    #{iterations => -1},
                    #{iterations => 1 bsl 32},
                    #{iterations => 1.0},
                    #{iterations => <<1>>},
                    #{unknown => 1}
                ]
            )
        end,
        Calls
    ),
    lists:foreach(
        fun(Length) ->
            badarg(fun() -> call(f1, [Key, TOPc, RAND, SQN, AMF, #{mac_length => Length}]) end),
            badarg(fun() -> call(f1_star, [Key, TOPc, RAND, SQN, AMF, #{mac_length => Length}]) end)
        end,
        [0, 4, 12, 64]
    ),
    lists:foreach(
        fun({Option, Length}) ->
            lists:foreach(
                fun(F) ->
                    badarg(fun() -> call(F, [Key, TOPc, RAND, #{Option => Length}]) end)
                end,
                [f2, f3, f4, f5, f2345]
            )
        end,
        [{res_length, 0}, {res_length, 6}, {res_length, 64}, {ck_length, 8}, {ck_length, 64}, {ik_length, 8}]
    ),
    badarg(fun() -> call(topc, [Key, TOP, #{mac_length => 8}]) end),
    badarg(fun() -> call(f1, [Key, TOPc, RAND, SQN, AMF, #{res_length => 8}]) end),
    badarg(fun() -> call(f2345, [Key, TOPc, RAND, #{mac_length => 8}]) end),
    badarg(fun() -> call(f5_star, [Key, TOPc, RAND, #{res_length => 8}]) end).

output_domains(_) ->
    {Key, TOP, RAND, SQN, AMF} = inputs(),
    TOPc = call(topc, [Key, TOP]),
    Short = call(f1, [Key, TOPc, RAND, SQN, AMF, #{mac_length => 8}]),
    Long = call(f1, [Key, TOPc, RAND, SQN, AMF, #{mac_length => 16}]),
    true = Short =/= binary:part(Long, 0, 8),
    MACStar = call(f1_star, [Key, TOPc, RAND, SQN, AMF]),
    true = Short =/= MACStar,
    {RES0, CK0, IK0, AK0} = call(f2345, [Key, TOPc, RAND]),
    lists:foreach(
        fun(Options) ->
            {RES1, CK1, IK1, AK1} = call(f2345, [Key, TOPc, RAND, Options]),
            true = RES0 =/= binary:part(RES1, 0, byte_size(RES0)),
            true = CK0 =/= binary:part(CK1, 0, byte_size(CK0)),
            true = IK0 =/= binary:part(IK1, 0, byte_size(IK0)),
            true = AK0 =/= AK1
        end,
        [#{res_length => 16}, #{ck_length => 32}, #{ik_length => 32}]
    ),
    true = AK0 =/= call(f5_star, [Key, TOPc, RAND]),
    Twice = call(topc, [Key, TOP, #{iterations => 2}]),
    true = TOPc =/= Twice,
    ok.

concurrent(_) ->
    Parent = self(),
    Workers = [
        spawn_monitor(fun() ->
            Key = binary:copy(
                <<Index>>,
                case Index rem 2 of
                    0 -> 16;
                    1 -> 32
                end
            ),
            TOP = binary:copy(<<(Index + 1)>>, 32),
            RAND = binary:copy(<<(Index + 2)>>, 16),
            Options = #{iterations => Index rem 3 + 1},
            TOPc = call(topc, [Key, TOP, Options]),
            Expected = call(f2345, [Key, TOPc, RAND, Options]),
            lists:foreach(
                fun(_) ->
                    TOPc = call(topc, [Key, TOP, Options]),
                    Expected = call(f2345, [Key, TOPc, RAND, Options])
                end,
                lists:seq(1, 100)
            ),
            Parent ! {self(), ok}
        end)
     || Index <- lists:seq(1, 12)
    ],
    lists:foreach(
        fun({Pid, Ref}) ->
            receive
                {Pid, ok} -> ok
            after 10000 -> ct:fail(tuak_timeout)
            end,
            receive
                {'DOWN', Ref, process, Pid, normal} -> ok
            after 10000 -> ct:fail(tuak_worker)
            end
        end,
        Workers
    ).

inputs() ->
    {
        binary:copy(<<16#AB>>, 16),
        binary:copy(<<16#55>>, 32),
        binary:copy(<<16#42>>, 16),
        binary:copy(<<16#11>>, 6),
        <<255, 255>>
    }.

hex(Name, V) -> binary:decode_hex(maps:get(Name, V)).
call(Function, Args) -> apply(libdecaf_nif, list_to_existing_atom("tuak_" ++ atom_to_list(Function)), Args).
replace(Index, Value, List) -> lists:sublist(List, Index - 1) ++ [Value | lists:nthtail(Index, List)].
badarg(Fun) ->
    try Fun() of
        Value -> ct:fail({expected_badarg, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _, _} -> ok
    end.
