%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2018, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  30 Nov 2018 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(spongerng_SUITE).

-include_lib("common_test/include/ct.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([spongerng_empty_deterministic/1]).
-export([spongerng_seed_deterministic/1]).

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
		{group, 'spongerng_init_from_buffer'},
		{group, 'spongerng_init_from_file'}
	].

groups() ->
	[
		{'spongerng_init_from_buffer', [parallel], [
			spongerng_empty_deterministic,
			spongerng_seed_deterministic
		]},
		{'spongerng_init_from_file', [parallel], [
			spongerng_seed_deterministic
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(libdecaf),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(libdecaf),
	ok.

init_per_group(G='spongerng_init_from_buffer', Config) ->
	EmptySponge = libdecaf_spongerng:init_from_buffer(<<>>, true),
	SeedSponge = libdecaf_spongerng:init_from_buffer(<<
		"To be, or not to be, that is the question:\n"
		"Whether 'tis nobler in the mind to suffer\n"
		"The slings and arrows of outrageous fortune,\n"
		"Or to take arms against a sea of troubles\n"
		"And by opposing end them.\n"
	>>, true),
	[
		{spongerng_empty_deterministic, [
			{EmptySponge, [
				{next, 16, hexstr2bin("2ed664354aa87699be93c3b62715a256")}
			]},
			{EmptySponge, [
				{next, 16, hexstr2bin("2ed664354aa87699be93c3b62715a256")},
				{next, 16, hexstr2bin("ddecd99a95a945ebe25b1d5e480d2eec")}
			]},
			{EmptySponge, [
				{next, 32, hexstr2bin("813f6b954fce5f6406403a8789013f795462d1c834802271e12f0186a9c13a0f")}
			]},
			{EmptySponge, [
				{next, 16, hexstr2bin("2ed664354aa87699be93c3b62715a256")},
				{next, 32, hexstr2bin("c9cdffa01ad44cd0acf5246c575ab96f48a8d8248f7ae9b92ccf06ea98d13151")}
			]},
			{EmptySponge, [
				{next, 0, hexstr2bin("")},
				{next, 16, hexstr2bin("79e70e5195841ded5af973c3ef106965")}
			]},
			{EmptySponge, [
				{stir, hexstr2bin("")},
				{next, 16, hexstr2bin("53314b16194e2d26cacc0c477b140c9c")}
			]},
			{EmptySponge, [
				{stir, hexstr2bin("")},
				{stir, hexstr2bin("")},
				{stir, hexstr2bin("")},
				{next, 16, hexstr2bin("fb25912a581d1f02311e9f8d4067aecc")}
			]}
		]},
		{spongerng_seed_deterministic, [
			{SeedSponge, [
				{next, 16, hexstr2bin("4c0e794c69bc27fd7fe77e7883059fe3")}
			]},
			{SeedSponge, [
				{next, 16, hexstr2bin("4c0e794c69bc27fd7fe77e7883059fe3")},
				{next, 16, hexstr2bin("57a3c0c7aa48d4097a703e66eeff564b")}
			]},
			{SeedSponge, [
				{next, 32, hexstr2bin("4384030c77811ddfe94fd6fcf015423c64df9f685aa826e89e54cc187d667d77")}
			]},
			{SeedSponge, [
				{next, 16, hexstr2bin("4c0e794c69bc27fd7fe77e7883059fe3")},
				{next, 32, hexstr2bin("bfaba4cf5c1e82888501e5c8c364dfec22e93dada338996496b80e7bff2ecb3b")}
			]},
			{SeedSponge, [
				{next, 0, hexstr2bin("")},
				{next, 16, hexstr2bin("039159696c4f84b0506d665eeb67348e")}
			]},
			{SeedSponge, [
				{stir, hexstr2bin("")},
				{next, 16, hexstr2bin("190dba9b4dc212f5e0a7fba06be82481")}
			]},
			{SeedSponge, [
				{stir, hexstr2bin("")},
				{stir, hexstr2bin("")},
				{stir, hexstr2bin("")},
				{next, 16, hexstr2bin("98218fc24cb2a0c80d6ec0bc8bb8385d")}
			]}
		]}
		| libdecaf_ct:start(G, Config)
	];
init_per_group(G='spongerng_init_from_file', Config) ->
	DataDir = ?config(data_dir, Config),
	SeedSponge = libdecaf_spongerng:init_from_file(filename:join(DataDir, "seed.txt"), 1406, true),
	[
		{spongerng_seed_deterministic, [
			{SeedSponge, [
				{next, 16, hexstr2bin("70636e1d0c39837c9b0df10ec4220cb7")}
			]},
			{SeedSponge, [
				{next, 16, hexstr2bin("70636e1d0c39837c9b0df10ec4220cb7")},
				{next, 16, hexstr2bin("fd9973511983c8fe924e84f9014fe306")}
			]},
			{SeedSponge, [
				{next, 32, hexstr2bin("c65214e298f835d6479ec485bfe341d7653f3454d65485147e7add8b2f6b96e1")}
			]},
			{SeedSponge, [
				{next, 16, hexstr2bin("70636e1d0c39837c9b0df10ec4220cb7")},
				{next, 32, hexstr2bin("396a4570fdf3a2dc23805ab177b293025a264e7b09f0d829cb0e8a50714fd230")}
			]},
			{SeedSponge, [
				{next, 0, hexstr2bin("")},
				{next, 16, hexstr2bin("41ac3e4cdeeb774e8f2eb482bcf7d0a6")}
			]},
			{SeedSponge, [
				{stir, hexstr2bin("")},
				{next, 16, hexstr2bin("15326577b668e7d67f87fcae7963beb2")}
			]},
			{SeedSponge, [
				{stir, hexstr2bin("")},
				{stir, hexstr2bin("")},
				{stir, hexstr2bin("")},
				{next, 16, hexstr2bin("764f476ae5b7cbff78358a4fdfcb43bc")}
			]}
		]}
		| libdecaf_ct:start(G, Config)
	].

end_per_group(_Group, Config) ->
	libdecaf_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

spongerng_empty_deterministic(Config) ->
	Vectors = ?config(spongerng_empty_deterministic, Config),
	lists:foreach(fun spongerng_deterministic/1, Vectors).

spongerng_seed_deterministic(Config) ->
	Vectors = ?config(spongerng_seed_deterministic, Config),
	lists:foreach(fun spongerng_deterministic/1, Vectors).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
spongerng_deterministic({Sponge = {spongerng, _}, Vectors}) when is_list(Vectors) ->
	_ = lists:foldl(fun spongerng_deterministic_vector/2, Sponge, Vectors),
	ok.

%% @private
spongerng_deterministic_vector({next, Outlen, Output}, Sponge0) ->
	case libdecaf_spongerng:next(Sponge0, Outlen) of
		{Sponge1 = {spongerng, _}, Output} ->
			Sponge1;
		{Sponge1 = {spongerng, _}, Badout} ->
			ct:fail({
				{libdecaf, next, [Sponge0, Outlen]},
				{expected, {Sponge1, hex:bin_to_hex(Output)}},
				{got, {Sponge1, hex:bin_to_hex(Badout)}}
			})
	end;
spongerng_deterministic_vector({stir, Input}, Sponge0) ->
	case libdecaf_spongerng:stir(Sponge0, Input) of
		Sponge1 = {spongerng, _} ->
			Sponge1
	end.

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
