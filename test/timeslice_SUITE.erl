%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  21 Jan 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(timeslice_SUITE).

-include_lib("common_test/include/ct.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

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
	end).

all() ->
	[
        {group, 'large_input_small_output'},
        {group, 'small_input_large_output'},
		{group, 'large_input_large_output'}
	].

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

init_per_suite(Config) ->
	_ = application:ensure_all_started(libdecaf),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(libdecaf),
	ok.

init_per_group(Group, Config) ->
    libdecaf_ct:start(Group, Config).

end_per_group(_Group, Config) ->
	libdecaf_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

large_input_small_output_sha2_512(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 64,
	Output = hexstr2bin("1e379c9db442923a072614e3b0baec085f87c7469ad8da21fbac4f4e889324e1f4df2de23b3f86d70f1f8b7a416676a14c2097e6084d87ca3b2bfbd0b66845d0"),
	?tv_ok(T0, libdecaf_nif, sha2_512_hash, [Input, OutputLen], Output),
	Ctx0 = libdecaf_nif:sha2_512_hash_init(),
	Ctx1 = libdecaf_nif:sha2_512_hash_update(Ctx0, Input),
	?tv_ok(T1, libdecaf_nif, sha2_512_hash_final, [Ctx1, OutputLen], Output),
	ok.

large_input_small_output_sha3_224(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 28,
	Output = hexstr2bin("174933dfefbbe9c59eda9db6dec81a847a901627cc2a4949b3479d99"),
	?tv_ok(T0, libdecaf_nif, sha3_224_hash, [Input, OutputLen], Output),
	Ctx0 = libdecaf_nif:sha3_224_hash_init(),
	Ctx1 = libdecaf_nif:sha3_224_hash_update(Ctx0, Input),
	?tv_ok(T1, libdecaf_nif, sha3_224_hash_final, [Ctx1, OutputLen], Output),
	ok.

large_input_small_output_sha3_256(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 32,
	Output = hexstr2bin("3934df79cd1c7b2de932f61588fafce5b03d3ed5db22b4d4ea3107af13c24d7c"),
	?tv_ok(T0, libdecaf_nif, sha3_256_hash, [Input, OutputLen], Output),
	Ctx0 = libdecaf_nif:sha3_256_hash_init(),
	Ctx1 = libdecaf_nif:sha3_256_hash_update(Ctx0, Input),
	?tv_ok(T1, libdecaf_nif, sha3_256_hash_final, [Ctx1, OutputLen], Output),
	ok.

large_input_small_output_sha3_384(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 48,
	Output = hexstr2bin("6d9730807f67612c7043f1e049cc0330550745de8b7f8ade111531ca7dec87967324720aca2dced888c16d5d8f44a942"),
	?tv_ok(T0, libdecaf_nif, sha3_384_hash, [Input, OutputLen], Output),
	Ctx0 = libdecaf_nif:sha3_384_hash_init(),
	Ctx1 = libdecaf_nif:sha3_384_hash_update(Ctx0, Input),
	?tv_ok(T1, libdecaf_nif, sha3_384_hash_final, [Ctx1, OutputLen], Output),
	ok.

large_input_small_output_sha3_512(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 64,
	Output = hexstr2bin("b50e11989f17c8532f14ff47c296d3be32d10d56d484254557d4bec2d9a8519c5fc3acd23331482b8c72fcb984f224c14447ec94332253d928ca92f38ba0e87b"),
	?tv_ok(T0, libdecaf_nif, sha3_512_hash, [Input, OutputLen], Output),
	Ctx0 = libdecaf_nif:sha3_512_hash_init(),
	Ctx1 = libdecaf_nif:sha3_512_hash_update(Ctx0, Input),
	?tv_ok(T1, libdecaf_nif, sha3_512_hash_final, [Ctx1, OutputLen], Output),
	ok.

large_input_small_output_shake128(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 16,
	Output = hexstr2bin("2b8f1c869e00111dc50eed54ccbf1388"),
	?tv_ok(T0, libdecaf_nif, shake128_xof, [Input, OutputLen], Output),
	Ctx0 = libdecaf_nif:shake128_xof_init(),
	Ctx1 = libdecaf_nif:shake128_xof_update(Ctx0, Input),
	{_Ctx2, Output} = libdecaf_nif:shake128_xof_output(Ctx1, OutputLen),
	ok.

large_input_small_output_shake256(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 32,
	Output = hexstr2bin("89d2ffc9994002f367b6501ff9d6f606076754e44b37f7871b882424ce3d701d"),
	?tv_ok(T0, libdecaf_nif, shake256_xof, [Input, OutputLen], Output),
	Ctx0 = libdecaf_nif:shake256_xof_init(),
	Ctx1 = libdecaf_nif:shake256_xof_update(Ctx0, Input),
	{_Ctx2, Output} = libdecaf_nif:shake256_xof_output(Ctx1, OutputLen),
	ok.

small_input_large_output_shake128(_Config) ->
	Input = binary:copy(<<0>>, 64),
	OutputLen = 20001,
	OutputHead = hexstr2bin("fc37fe19d48ad68ba1f793aa126f5f14"),
	OutputTail = hexstr2bin("028fd3782a8accd4270f1ec849589c9d"),
	OutputSkip = (OutputLen - byte_size(OutputHead) - byte_size(OutputTail)),
	case libdecaf_nif:shake128_xof(Input, OutputLen) of
		<<OutputHead:16/binary, _:OutputSkip/binary, OutputTail:16/binary>> ->
			ok;
		T0 ->
			ct:fail({{libdecaf_nif, shake128_xof, [Input, OutputLen]}, {expected, {OutputHead, OutputTail}}, {got, T0}})
	end,
	Ctx0 = libdecaf_nif:shake128_xof_init(),
	Ctx1 = libdecaf_nif:shake128_xof_update(Ctx0, Input),
	{Ctx2, OutputHead} = libdecaf_nif:shake128_xof_output(Ctx1, byte_size(OutputHead)),
	{Ctx3, _} = libdecaf_nif:shake128_xof_output(Ctx2, OutputSkip),
	{_Ctx4, OutputTail} = libdecaf_nif:shake128_xof_output(Ctx3, byte_size(OutputTail)),
	ok.

small_input_large_output_shake256(_Config) ->
	Input = binary:copy(<<0>>, 64),
	OutputLen = 20001,
	OutputHead = hexstr2bin("7ea5f2ea9e9487de4753918bbf5308eb"),
	OutputTail = hexstr2bin("08d24cb93b1b17219735f56c6208361f"),
	OutputSkip = (OutputLen - byte_size(OutputHead) - byte_size(OutputTail)),
	case libdecaf_nif:shake256_xof(Input, OutputLen) of
		<<OutputHead:16/binary, _:OutputSkip/binary, OutputTail:16/binary>> ->
			ok;
		T0 ->
			ct:fail({{libdecaf_nif, shake256_xof, [Input, OutputLen]}, {expected, {OutputHead, OutputTail}}, {got, T0}})
	end,
	Ctx0 = libdecaf_nif:shake256_xof_init(),
	Ctx1 = libdecaf_nif:shake256_xof_update(Ctx0, Input),
	{Ctx2, OutputHead} = libdecaf_nif:shake256_xof_output(Ctx1, byte_size(OutputHead)),
	{Ctx3, _} = libdecaf_nif:shake256_xof_output(Ctx2, OutputSkip),
	{_Ctx4, OutputTail} = libdecaf_nif:shake256_xof_output(Ctx3, byte_size(OutputTail)),
	ok.

large_input_large_output_shake128(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 20001,
	OutputHead = hexstr2bin("2b8f1c869e00111dc50eed54ccbf1388"),
	OutputTail = hexstr2bin("953d5b23e0641411fa4fc38c4ecafa15"),
	OutputSkip = (OutputLen - byte_size(OutputHead) - byte_size(OutputTail)),
	case libdecaf_nif:shake128_xof(Input, OutputLen) of
		<<OutputHead:16/binary, _:OutputSkip/binary, OutputTail:16/binary>> ->
			ok;
		T0 ->
			ct:fail({{libdecaf_nif, shake256_xof, [Input, OutputLen]}, {expected, {OutputHead, OutputTail}}, {got, T0}})
	end,
	Ctx0 = libdecaf_nif:shake128_xof_init(),
	Ctx1 = libdecaf_nif:shake128_xof_update(Ctx0, Input),
	{Ctx2, OutputHead} = libdecaf_nif:shake128_xof_output(Ctx1, byte_size(OutputHead)),
	{Ctx3, _} = libdecaf_nif:shake128_xof_output(Ctx2, OutputSkip),
	{_Ctx4, OutputTail} = libdecaf_nif:shake128_xof_output(Ctx3, byte_size(OutputTail)),
	ok.

large_input_large_output_shake256(_Config) ->
	Input = binary:copy(<<0>>, 20001),
	OutputLen = 20001,
	OutputHead = hexstr2bin("89d2ffc9994002f367b6501ff9d6f606"),
	OutputTail = hexstr2bin("77d381030036230930dd690f2315e370"),
	OutputSkip = (OutputLen - byte_size(OutputHead) - byte_size(OutputTail)),
	case libdecaf_nif:shake256_xof(Input, OutputLen) of
		<<OutputHead:16/binary, _:OutputSkip/binary, OutputTail:16/binary>> ->
			ok;
		T0 ->
			ct:fail({{libdecaf_nif, shake256_xof, [Input, OutputLen]}, {expected, {OutputHead, OutputTail}}, {got, T0}})
	end,
	Ctx0 = libdecaf_nif:shake256_xof_init(),
	Ctx1 = libdecaf_nif:shake256_xof_update(Ctx0, Input),
	{Ctx2, OutputHead} = libdecaf_nif:shake256_xof_output(Ctx1, byte_size(OutputHead)),
	{Ctx3, _} = libdecaf_nif:shake256_xof_output(Ctx2, OutputSkip),
	{_Ctx4, OutputTail} = libdecaf_nif:shake256_xof_output(Ctx3, byte_size(OutputTail)),
	ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
hexstr2bin(S) ->
	list_to_binary(hexstr2list(S)).

%% @private
hexstr2list([X,Y|T]) ->
	[mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
	[].

%% @private
mkint(C) when $0 =< C, C =< $9 ->
	C - $0;
mkint(C) when $A =< C, C =< $F ->
	C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
	C - $a + 10.
