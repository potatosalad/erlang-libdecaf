%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  29 Feb 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(fips180_4_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("public_key/include/public_key.hrl").
-include_lib("stdlib/include/zip.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([fips180_4/1]).

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
		{group, 'shabytetestvectors'}
	].

groups() ->
	[
		{'shabytetestvectors', [], [
			fips180_4
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(libdecaf),
	data_setup(Config).

end_per_suite(_Config) ->
	_ = application:stop(libdecaf),
	ok.

init_per_group(G='shabytetestvectors', Config) ->
	Folder = data_file("shabytetestvectors", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{'fips180-4_files', Files} | libdecaf_ct:start(G, Config)].

end_per_group(_Group, Config) ->
	libdecaf_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

fips180_4(Config) ->
	Files = [File || File <- ?config('fips180-4_files', Config)],
	lists:foldl(fun fips180_4/2, Config, Files).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
data_setup(Config) ->
	lists:foldl(fun(F, C) ->
		io:format(user, "\e[0;36m[FETCH] ~s\e[0m", [F]),
		{ok, Progress} = libdecaf_ct:progress_start(),
		NewC = data_setup(F, C),
		ok = libdecaf_ct:progress_stop(Progress),
		NewC
	end, Config, [
		"shabytetestvectors"
	]).

%% @private
data_setup(F = "shabytetestvectors", Config) ->
	BaseURL = "https://raw.githubusercontent.com/coruus/nist-testvectors/2841a2d486a155c8c79c1e6b2fe5a653e7276d96/csrc.nist.gov/groups/STM/cavp/documents/shs/shabytetestvectors/",
	Files = [
		"SHA512LongMsg.rsp",
		"SHA512ShortMsg.rsp"
	],
	URLs = [BaseURL ++ File || File <- Files],
	Directory = data_file(F, Config),
	DataFiles = [data_file(filename:join(F, File), Config) || File <- Files],
	ok = data_setup_multiple(DataFiles, Directory, URLs),
	Config.

%% @private
data_setup_multiple([DataFile | DataFiles], Directory, [URL | URLs]) ->
	case filelib:is_dir(Directory) of
		true ->
			ok;
		false ->
			ok = file:make_dir(Directory)
	end,
	case filelib:is_file(DataFile) of
		true ->
			ok;
		false ->
			ok = fetch:fetch(URL, DataFile)
	end,
	data_setup_multiple(DataFiles, Directory, URLs);
data_setup_multiple([], _Directory, []) ->
	ok.

%% @private
fips180_4(File, Config) ->
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [filename:basename(File)]),
	fips180_4_test(Vectors, Config).

%% @private
fips180_4_test([
			{option, {<<"L">>, LBin}}
			| Vectors
		], Config) ->
	LInt = binary_to_integer(LBin),
	fips180_4_test(Vectors, LInt, Config);
fips180_4_test([Vector | _Vectors], _Config) ->
	ct:fail("Unhandled test vector: ~p~n", [Vector]).

%% @private
fips180_4_test([
			{vector, {<<"Len">>, Len}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"MD">>, MD}, _}
			| Vectors
		], OutputByteLen, Config) when Len rem 8 =:= 0 ->
	InputBytes = binary:part(Msg, 0, Len div 8),
	?tv_ok(T0, libdecaf_sha2, hash, [sha2_512, InputBytes, OutputByteLen], MD),
	Context0 = libdecaf_sha2:init(sha2_512),
	Context1 = libdecaf_sha2:update(Context0, InputBytes),
	?tv_ok(T1, libdecaf_sha2, final, [Context1, OutputByteLen], MD),
	fips180_4_test(Vectors, OutputByteLen, Config);
% fips180_4_test([
% 			{vector, {<<"Seed">>, Seed}, _}
% 			| Vectors
% 		], OutputByteLen, Config) ->
% 	fips180_4_test(Vectors, Seed, OutputByteLen, Config);
fips180_4_test([], _OutputByteLen, _Config) ->
	ok;
fips180_4_test(Vectors, _Opts, _Config) ->
	ct:fail("Unhandled test vectors: ~p~n", [Vectors]),
	ok.

% %% @private
% fips180_4_test([
% 			{vector, {<<"COUNT">>, Count}, _},
% 			{vector, {<<"MD">>, MD}, _}
% 			| Vectors
% 		], InputBytes, OutputByteLen, Config) ->
% 	io:format("\tCOUNT = ~w", [Count]),
% 	?tv_ok(T0, libdecaf_sha2, hash, [sha2_512, InputBytes, OutputByteLen], MD),
% 	Context0 = libdecaf_sha2:init(sha2_512),
% 	Context1 = libdecaf_sha2:update(Context0, InputBytes),
% 	?tv_ok(T1, libdecaf_sha2, final, [Context1, OutputByteLen], MD),
% 	fips180_4_test(Vectors, MD, OutputByteLen, Config);
% fips180_4_test([], _Seed, _OutputByteLen, _Config) ->
% 	ok;
% fips180_4_test(Vectors, _Seed, _OutputByteLen, _Config) ->
% 	ct:fail("Unhandled test vectors: ~p~n", [Vectors]).
