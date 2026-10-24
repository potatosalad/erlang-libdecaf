%%% % @format
-module(timeslice_SUITE).
-compile(warn_missing_spec_all).
-moduledoc """
Common Test coverage for scheduler timeslicing in hash and SHAKE operations.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2022-01-21", modified => "2026-10-22"}.
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

%% ct.
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2
]).

%% Tests.
-export([
    large_input_small_output_sha2_512/1,
    large_input_small_output_sha3_224/1,
    large_input_small_output_sha3_256/1,
    large_input_small_output_sha3_384/1,
    large_input_small_output_sha3_512/1,
    large_input_small_output_shake128/1,
    large_input_small_output_shake256/1,
    small_input_large_output_shake128/1,
    small_input_large_output_shake256/1,
    large_input_large_output_shake128/1,
    large_input_large_output_shake256/1
]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
    case erlang:apply(M, F, A) of
        E ->
            ok;
        T ->
            ct:fail({{M, F, A}, {expected, E}, {got, T}})
    end
).

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [
        {group, 'large_input_small_output'},
        {group, 'small_input_large_output'},
        {group, 'large_input_large_output'}
    ].

-spec groups() -> Result when Result :: [ct_suite:ct_group_def()].
groups() ->
    [
        {'large_input_small_output', [parallel], [
            large_input_small_output_sha2_512,
            large_input_small_output_sha3_224,
            large_input_small_output_sha3_256,
            large_input_small_output_sha3_384,
            large_input_small_output_sha3_512,
            large_input_small_output_shake128,
            large_input_small_output_shake256
        ]},
        {'small_input_large_output', [parallel], [
            small_input_large_output_shake128,
            small_input_large_output_shake256
        ]},
        {'large_input_large_output', [parallel], [
            large_input_large_output_shake128,
            large_input_large_output_shake256
        ]}
    ].

-spec init_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_suite(Config) ->
    _ = application:ensure_all_started(libdecaf),
    Config.

-spec end_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
end_per_suite(_Config) ->
    _ = application:stop(libdecaf),
    ok.

-spec init_per_group(Group, Config) -> Result when
    Group :: ct_suite:ct_groupname(), Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_group(Group, Config) ->
    libdecaf_ct:start(Group, Config).

-spec end_per_group(Group, Config) -> Result when
    Group :: ct_suite:ct_groupname(), Config :: ct_suite:ct_config(), Result :: ok.
end_per_group(_Group, Config) ->
    libdecaf_ct:stop(Config),
    ok.

%%====================================================================
%% Tests
%%====================================================================

-spec large_input_small_output_sha2_512(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_small_output_sha2_512(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 64,
    Output = hexstr2bin(
        "1e379c9db442923a072614e3b0baec085f87c7469ad8da21fbac4f4e889324e1f4df2de23b3f86d70f1f8b7a416676a14c2097e6084d87ca3b2bfbd0b66845d0"
    ),
    ?tv_ok(T0, libdecaf_nif, hash, [{sha2_512, OutputLen}, Input], Output),
    Ctx0 = libdecaf_nif:hash_init({sha2_512, OutputLen}),
    Ctx1 = libdecaf_nif:hash_update(Ctx0, Input),
    ?tv_ok(T1, libdecaf_nif, hash_final, [Ctx1], Output),
    ok.

-spec large_input_small_output_sha3_224(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_small_output_sha3_224(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 28,
    Output = hexstr2bin("174933dfefbbe9c59eda9db6dec81a847a901627cc2a4949b3479d99"),
    ?tv_ok(T0, libdecaf_nif, hash, [{sha3_224, OutputLen}, Input], Output),
    Ctx0 = libdecaf_nif:hash_init({sha3_224, OutputLen}),
    Ctx1 = libdecaf_nif:hash_update(Ctx0, Input),
    ?tv_ok(T1, libdecaf_nif, hash_final, [Ctx1], Output),
    ok.

-spec large_input_small_output_sha3_256(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_small_output_sha3_256(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 32,
    Output = hexstr2bin("3934df79cd1c7b2de932f61588fafce5b03d3ed5db22b4d4ea3107af13c24d7c"),
    ?tv_ok(T0, libdecaf_nif, hash, [{sha3_256, OutputLen}, Input], Output),
    Ctx0 = libdecaf_nif:hash_init({sha3_256, OutputLen}),
    Ctx1 = libdecaf_nif:hash_update(Ctx0, Input),
    ?tv_ok(T1, libdecaf_nif, hash_final, [Ctx1], Output),
    ok.

-spec large_input_small_output_sha3_384(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_small_output_sha3_384(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 48,
    Output = hexstr2bin(
        "6d9730807f67612c7043f1e049cc0330550745de8b7f8ade111531ca7dec87967324720aca2dced888c16d5d8f44a942"
    ),
    ?tv_ok(T0, libdecaf_nif, hash, [{sha3_384, OutputLen}, Input], Output),
    Ctx0 = libdecaf_nif:hash_init({sha3_384, OutputLen}),
    Ctx1 = libdecaf_nif:hash_update(Ctx0, Input),
    ?tv_ok(T1, libdecaf_nif, hash_final, [Ctx1], Output),
    ok.

-spec large_input_small_output_sha3_512(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_small_output_sha3_512(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 64,
    Output = hexstr2bin(
        "b50e11989f17c8532f14ff47c296d3be32d10d56d484254557d4bec2d9a8519c5fc3acd23331482b8c72fcb984f224c14447ec94332253d928ca92f38ba0e87b"
    ),
    ?tv_ok(T0, libdecaf_nif, hash, [{sha3_512, OutputLen}, Input], Output),
    Ctx0 = libdecaf_nif:hash_init({sha3_512, OutputLen}),
    Ctx1 = libdecaf_nif:hash_update(Ctx0, Input),
    ?tv_ok(T1, libdecaf_nif, hash_final, [Ctx1], Output),
    ok.

-spec large_input_small_output_shake128(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_small_output_shake128(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 16,
    Output = hexstr2bin("2b8f1c869e00111dc50eed54ccbf1388"),
    ?tv_ok(T0, libdecaf_nif, xof, [shake128, Input, OutputLen], Output),
    Ctx0 = libdecaf_nif:xof_init(shake128),
    Ctx1 = libdecaf_nif:xof_absorb(Ctx0, Input),
    {_Ctx2, Output} = libdecaf_nif:xof_squeeze(Ctx1, OutputLen),
    ok.

-spec large_input_small_output_shake256(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_small_output_shake256(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 32,
    Output = hexstr2bin("89d2ffc9994002f367b6501ff9d6f606076754e44b37f7871b882424ce3d701d"),
    ?tv_ok(T0, libdecaf_nif, xof, [shake256, Input, OutputLen], Output),
    Ctx0 = libdecaf_nif:xof_init(shake256),
    Ctx1 = libdecaf_nif:xof_absorb(Ctx0, Input),
    {_Ctx2, Output} = libdecaf_nif:xof_squeeze(Ctx1, OutputLen),
    ok.

-spec small_input_large_output_shake128(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
small_input_large_output_shake128(_Config) ->
    Input = binary:copy(<<0>>, 64),
    OutputLen = 20001,
    OutputHead = hexstr2bin("fc37fe19d48ad68ba1f793aa126f5f14"),
    OutputTail = hexstr2bin("028fd3782a8accd4270f1ec849589c9d"),
    OutputSkip = (OutputLen - byte_size(OutputHead) - byte_size(OutputTail)),
    case libdecaf_nif:xof(shake128, Input, OutputLen) of
        <<OutputHead:16/binary, _:OutputSkip/binary, OutputTail:16/binary>> ->
            ok;
        T0 ->
            ct:fail({{libdecaf_nif, xof, [shake128, Input, OutputLen]}, {expected, {OutputHead, OutputTail}}, {got, T0}})
    end,
    Ctx0 = libdecaf_nif:xof_init(shake128),
    Ctx1 = libdecaf_nif:xof_absorb(Ctx0, Input),
    {Ctx2, OutputHead} = libdecaf_nif:xof_squeeze(Ctx1, byte_size(OutputHead)),
    {Ctx3, _} = libdecaf_nif:xof_squeeze(Ctx2, OutputSkip),
    {_Ctx4, OutputTail} = libdecaf_nif:xof_squeeze(Ctx3, byte_size(OutputTail)),
    ok.

-spec small_input_large_output_shake256(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
small_input_large_output_shake256(_Config) ->
    Input = binary:copy(<<0>>, 64),
    OutputLen = 20001,
    OutputHead = hexstr2bin("7ea5f2ea9e9487de4753918bbf5308eb"),
    OutputTail = hexstr2bin("08d24cb93b1b17219735f56c6208361f"),
    OutputSkip = (OutputLen - byte_size(OutputHead) - byte_size(OutputTail)),
    case libdecaf_nif:xof(shake256, Input, OutputLen) of
        <<OutputHead:16/binary, _:OutputSkip/binary, OutputTail:16/binary>> ->
            ok;
        T0 ->
            ct:fail({{libdecaf_nif, xof, [shake256, Input, OutputLen]}, {expected, {OutputHead, OutputTail}}, {got, T0}})
    end,
    Ctx0 = libdecaf_nif:xof_init(shake256),
    Ctx1 = libdecaf_nif:xof_absorb(Ctx0, Input),
    {Ctx2, OutputHead} = libdecaf_nif:xof_squeeze(Ctx1, byte_size(OutputHead)),
    {Ctx3, _} = libdecaf_nif:xof_squeeze(Ctx2, OutputSkip),
    {_Ctx4, OutputTail} = libdecaf_nif:xof_squeeze(Ctx3, byte_size(OutputTail)),
    ok.

-spec large_input_large_output_shake128(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_large_output_shake128(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 20001,
    OutputHead = hexstr2bin("2b8f1c869e00111dc50eed54ccbf1388"),
    OutputTail = hexstr2bin("953d5b23e0641411fa4fc38c4ecafa15"),
    OutputSkip = (OutputLen - byte_size(OutputHead) - byte_size(OutputTail)),
    case libdecaf_nif:xof(shake128, Input, OutputLen) of
        <<OutputHead:16/binary, _:OutputSkip/binary, OutputTail:16/binary>> ->
            ok;
        T0 ->
            ct:fail({{libdecaf_nif, xof, [shake256, Input, OutputLen]}, {expected, {OutputHead, OutputTail}}, {got, T0}})
    end,
    Ctx0 = libdecaf_nif:xof_init(shake128),
    Ctx1 = libdecaf_nif:xof_absorb(Ctx0, Input),
    {Ctx2, OutputHead} = libdecaf_nif:xof_squeeze(Ctx1, byte_size(OutputHead)),
    {Ctx3, _} = libdecaf_nif:xof_squeeze(Ctx2, OutputSkip),
    {_Ctx4, OutputTail} = libdecaf_nif:xof_squeeze(Ctx3, byte_size(OutputTail)),
    ok.

-spec large_input_large_output_shake256(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
large_input_large_output_shake256(_Config) ->
    Input = binary:copy(<<0>>, 20001),
    OutputLen = 20001,
    OutputHead = hexstr2bin("89d2ffc9994002f367b6501ff9d6f606"),
    OutputTail = hexstr2bin("77d381030036230930dd690f2315e370"),
    OutputSkip = (OutputLen - byte_size(OutputHead) - byte_size(OutputTail)),
    case libdecaf_nif:xof(shake256, Input, OutputLen) of
        <<OutputHead:16/binary, _:OutputSkip/binary, OutputTail:16/binary>> ->
            ok;
        T0 ->
            ct:fail({{libdecaf_nif, xof, [shake256, Input, OutputLen]}, {expected, {OutputHead, OutputTail}}, {got, T0}})
    end,
    Ctx0 = libdecaf_nif:xof_init(shake256),
    Ctx1 = libdecaf_nif:xof_absorb(Ctx0, Input),
    {Ctx2, OutputHead} = libdecaf_nif:xof_squeeze(Ctx1, byte_size(OutputHead)),
    {Ctx3, _} = libdecaf_nif:xof_squeeze(Ctx2, OutputSkip),
    {_Ctx4, OutputTail} = libdecaf_nif:xof_squeeze(Ctx3, byte_size(OutputTail)),
    ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
-spec hexstr2bin(Hex) -> Result when Hex :: string(), Result :: binary().
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

%% @private
-spec hexstr2list(Hex) -> Result when Hex :: string(), Result :: [byte()].
hexstr2list([X, Y | T]) ->
    [mkint(X) * 16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

%% @private
-spec mkint(Character) -> Result when Character :: char(), Result :: 0..15.
mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.
