%%% % @format
-module(rfc9496_SUITE).
-include_lib("common_test/include/ct.hrl").
-export([
    all/0,
    documentation/1,
    end_per_group/2,
    end_per_suite/1,
    group_laws/1,
    groups/0,
    init_per_group/2,
    init_per_suite/1,
    invalid_arguments/1,
    invalid_encodings/1,
    multiples/1,
    precomputed/1,
    scalars/1,
    uniform_bytes/1
]).

all() -> [{group, ristretto255}, {group, decaf448}].
groups() ->
    [
        {G, [parallel], [
            multiples,
            invalid_encodings,
            uniform_bytes,
            scalars,
            group_laws,
            precomputed,
            invalid_arguments,
            documentation
        ]}
     || G <- [ristretto255, decaf448]
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libdecaf),
    {ok, Vectors} = file:consult(filename:join(?config(data_dir, Config), "vectors.config")),
    [{vectors, Vectors} | Config].
end_per_suite(_Config) -> ok.
init_per_group(Group, Config) ->
    {Module, Bytes, Order} = group(Group),
    [
        {module, Module},
        {bytes, Bytes},
        {order, Order}
        | proplists:get_value(Group, ?config(vectors, Config))
    ] ++ Config.
end_per_group(_, _) -> ok.

group(ristretto255) ->
    {libdecaf_ristretto255, 32, (1 bsl 252) + 27742317777372353535851937790883648493};
group(decaf448) ->
    {libdecaf_decaf448, 56,
        (1 bsl 446) - 13818066809895115352007386748515426880336692474882178609894547503885}.

%% RFC 9496 A.1 and B.1: all 16 encodings, addition, and multiplication.
multiples(Config) ->
    M = ?config(module, Config),
    N = ?config(bytes, Config),
    Points = [hex(V) || V <- ?config(multiples, Config)],
    Identity = hd(Points),
    Identity = M:identity(),
    Base = lists:nth(2, Points),
    Base = M:base(),
    Table = M:precompute(Base),
    lists:foldl(
        fun(Expected, {I, Previous}) ->
            Expected = Previous,
            true = M:point_is_valid(Expected),
            Scalar = integer(I, N),
            Expected = M:base_scalarmul(Scalar),
            Expected = M:point_scalarmul(Base, Scalar),
            Expected = M:precomputed_scalarmul(Table, Scalar),
            {I + 1, M:point_add(Previous, Base)}
        end,
        {0, Identity},
        Points
    ),
    ok.

%% RFC 9496 A.2 and B.2: every prohibited encoding must be rejected.
invalid_encodings(Config) ->
    M = ?config(module, Config),
    Base = M:base(),
    lists:foreach(
        fun(V) ->
            Invalid = hex(V),
            false = M:point_is_valid(Invalid),
            badarg(fun() -> M:point_add(Invalid, Base) end),
            badarg(fun() -> M:point_eq(Base, Invalid) end)
        end,
        ?config(invalid, Config)
    ).

%% RFC 9496 A.3 and B.3, including all four equivalent ristretto inputs.
uniform_bytes(Config) ->
    M = ?config(module, Config),
    lists:foreach(
        fun({I, O}) ->
            Expected = hex(O),
            Expected = M:point_from_hash(hex(I))
        end,
        ?config(uniform, Config)
    ).

scalars(Config) ->
    M = ?config(module, Config),
    N = ?config(bytes, Config),
    L = ?config(order, Config),
    Zero = integer(0, N),
    One = integer(1, N),
    Zero = M:scalar_reduce(<<>>),
    Zero = M:scalar_reduce(integer(L, N)),
    false = M:scalar_is_canonical(integer(L, N)),
    false = M:scalar_is_canonical(integer(L + 1, N)),
    error = M:scalar_invert(Zero),
    lists:foreach(
        fun({A, B}) ->
            SA = integer(A, N),
            SB = integer(B, N),
            true = M:scalar_is_canonical(SA),
            Add = integer((A + B) rem L, N),
            Add = M:scalar_add(SA, SB),
            Sub = integer((A - B + L) rem L, N),
            Sub = M:scalar_sub(SA, SB),
            Mul = integer((A * B) rem L, N),
            Mul = M:scalar_mul(SA, SB),
            Zero = M:scalar_add(SA, M:scalar_negate(SA)),
            SA = M:scalar_add(M:scalar_halve(SA), M:scalar_halve(SA)),
            case A of
                0 -> ok;
                _ -> One = M:scalar_mul(SA, M:scalar_invert(SA))
            end
        end,
        [{0, 0}, {1, 2}, {L - 1, L - 1}, {L div 2, 65537}]
    ),
    Wide = binary:copy(<<255>>, N * 2),
    Reduced = integer(binary:decode_unsigned(Wide, little) rem L, N),
    Reduced = M:scalar_reduce(Wide),
    lists:foreach(fun(_) -> true = M:scalar_is_canonical(M:scalar_random()) end, lists:seq(1, 10)),
    ok.

group_laws(Config) ->
    M = ?config(module, Config),
    N = ?config(bytes, Config),
    S0 = integer(0, N),
    S1 = integer(1, N),
    S2 = integer(2, N),
    S3 = integer(3, N),
    I = M:identity(),
    B = M:base(),
    P = M:base_scalarmul(S2),
    Q = M:base_scalarmul(S3),
    B = M:point_sub(Q, P),
    I = M:point_sub(P, P),
    I = M:point_add(P, M:point_negate(P)),
    I = M:point_scalarmul(B, S0),
    I = M:point_scalarmul(I, S3),
    P = M:point_scalarmul(P, S1),
    Double = M:point_add(P, P),
    Double = M:point_double(P),
    Combo = M:base_scalarmul(integer(13, N)),
    Combo = M:point_double_scalarmul(P, S2, Q, S3),
    I = M:point_double_scalarmul(P, S0, Q, S0),
    true = M:point_eq(B, B),
    false = M:point_eq(P, Q),
    A = binary:copy(<<19>>, N),
    C = binary:copy(<<43>>, N),
    Mapped = M:point_add(M:point_from_hash_nonuniform(A), M:point_from_hash_nonuniform(C)),
    Mapped = M:point_from_hash(<<A/binary, C/binary>>),
    ok.

precomputed(Config) ->
    M = ?config(module, Config),
    N = ?config(bytes, Config),
    S = integer(17, N),
    P = M:base_scalarmul(integer(5, N)),
    Table = M:precompute(P),
    Expected = M:point_scalarmul(P, S),
    Expected = M:precomputed_scalarmul(Table, S),
    Parent = self(),
    {Pid, Monitor} = spawn_monitor(fun() -> Parent ! {self(), M:precomputed_scalarmul(Table, S)} end),
    receive
        {Pid, Expected} -> ok
    after 5000 -> ct:fail(precomputed_timeout)
    end,
    receive
        {'DOWN', Monitor, process, Pid, normal} -> ok
    after 5000 -> ct:fail(precomputed_process)
    end,
    Other =
        case M of
            libdecaf_ristretto255 -> libdecaf_decaf448;
            _ -> libdecaf_ristretto255
        end,
    badarg(fun() -> Other:precomputed_scalarmul(Table, Other:scalar_reduce(<<1>>)) end),
    ok.

invalid_arguments(Config) ->
    M = ?config(module, Config),
    N = ?config(bytes, Config),
    L = ?config(order, Config),
    B = M:base(),
    Short = binary:copy(<<0>>, N - 1),
    Noncanonical = integer(L, N),
    false = M:point_is_valid(Short),
    false = M:point_is_valid(not_a_point),
    false = M:scalar_is_canonical(Short),
    false = M:scalar_is_canonical(not_a_scalar),
    lists:foreach(fun(F) -> badarg(F) end, [
        fun() -> M:point_add(B, Short) end,
        fun() -> M:point_sub(Short, B) end,
        fun() -> M:point_negate(Short) end,
        fun() -> M:point_double(Short) end,
        fun() -> M:point_scalarmul(B, Noncanonical) end,
        fun() -> M:base_scalarmul(Noncanonical) end,
        fun() -> M:point_double_scalarmul(B, M:scalar_reduce(<<1>>), Short, Noncanonical) end,
        fun() -> M:point_from_hash(<<>>) end,
        fun() -> M:point_from_hash_nonuniform(Short) end,
        fun() -> M:precompute(Short) end,
        fun() -> M:precomputed_scalarmul(make_ref(), M:scalar_reduce(<<1>>)) end,
        fun() -> M:scalar_add(Noncanonical, M:scalar_reduce(<<1>>)) end,
        fun() -> M:scalar_sub(M:scalar_reduce(<<1>>), Noncanonical) end,
        fun() -> M:scalar_mul(Short, Short) end,
        fun() -> M:scalar_negate(Noncanonical) end,
        fun() -> M:scalar_halve(Noncanonical) end,
        fun() -> M:scalar_invert(Noncanonical) end,
        fun() -> M:scalar_reduce(not_a_binary) end
    ]),
    ok.

%% Keep the examples that users copy from the generated API documentation executable.
documentation(Config) ->
    Module = ?config(module, Config),
    {ok, {docs_v1, _, erlang, <<"text/markdown">>, ModuleDoc, _, Entries}} = code:get_doc(Module),
    FunctionDocs = [Doc || {{function, _, _}, _, _, Doc, _} <- Entries],
    Examples = lists:append([
        case
            re:run(maps:get(<<"en">>, Doc), <<"```erlang\\n(.*?)```">>, [
                global, dotall, {capture, [1], binary}
            ])
        of
            {match, Matches} -> [Example || [Example] <- Matches];
            nomatch -> []
        end
     || Doc <- [ModuleDoc | FunctionDocs]
    ]),
    [_ | _] = Examples,
    lists:foreach(
        fun(Example) ->
            {ok, Tokens, _} = erl_scan:string(unicode:characters_to_list(Example)),
            {ok, Expressions} = erl_parse:parse_exprs(Tokens),
            {value, _, _} = erl_eval:exprs(Expressions, erl_eval:new_bindings())
        end,
        Examples
    ),
    ok.

integer(I, Bytes) -> <<I:(Bytes * 8)/little>>.
hex(S) -> list_to_binary([list_to_integer([A, B], 16) || [A, B] <- pairs(S)]).
pairs([]) -> [];
pairs([A, B | Rest]) -> [[A, B] | pairs(Rest)].
badarg(F) ->
    try F() of
        V -> ct:fail({expected_badarg, V})
    catch
        error:badarg -> ok
    end.
