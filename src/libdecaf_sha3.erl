%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  29 Feb 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libdecaf_sha3).

%% API
-export([hash/2]).
-export([hash/3]).
-export([init/1]).
-export([update/2]).
-export([final/1]).
-export([final/2]).

%% Macros
-define(WRAP_STATE(T, R),
	case R of
		NewState when is_reference(NewState) ->
			{T, NewState};
		Other ->
			Other
	end).

%%%===================================================================
%%% API functions
%%%===================================================================

hash(sha3_224, In) ->
	libdecaf:sha3_224(In);
hash(sha3_256, In) ->
	libdecaf:sha3_256(In);
hash(sha3_384, In) ->
	libdecaf:sha3_384(In);
hash(sha3_512, In) ->
	libdecaf:sha3_512(In);
hash(Type, In) ->
	erlang:error({badarg, [Type, In]}).

hash(sha3_224, In, Outlen) ->
	libdecaf:sha3_224(In, Outlen);
hash(sha3_256, In, Outlen) ->
	libdecaf:sha3_256(In, Outlen);
hash(sha3_384, In, Outlen) ->
	libdecaf:sha3_384(In, Outlen);
hash(sha3_512, In, Outlen) ->
	libdecaf:sha3_512(In, Outlen);
hash(shake128, In, Outlen) ->
	libdecaf:shake128(In, Outlen);
hash(shake256, In, Outlen) ->
	libdecaf:shake256(In, Outlen);
hash(Type, In, Outlen) ->
	erlang:error({badarg, [Type, In, Outlen]}).

init(sha3_224) ->
	?WRAP_STATE(sha3_224, libdecaf:sha3_224_init());
init(sha3_256) ->
	?WRAP_STATE(sha3_256, libdecaf:sha3_256_init());
init(sha3_384) ->
	?WRAP_STATE(sha3_384, libdecaf:sha3_384_init());
init(sha3_512) ->
	?WRAP_STATE(sha3_512, libdecaf:sha3_512_init());
init(shake128) ->
	?WRAP_STATE(shake128, libdecaf:shake128_init());
init(shake256) ->
	?WRAP_STATE(shake256, libdecaf:shake256_init());
init(Type) ->
	erlang:error({badarg, [Type]}).

update({T = sha3_224, State}, In) ->
	?WRAP_STATE(T, libdecaf:sha3_224_update(State, In));
update({T = sha3_256, State}, In) ->
	?WRAP_STATE(T, libdecaf:sha3_256_update(State, In));
update({T = sha3_384, State}, In) ->
	?WRAP_STATE(T, libdecaf:sha3_384_update(State, In));
update({T = sha3_512, State}, In) ->
	?WRAP_STATE(T, libdecaf:sha3_512_update(State, In));
update({T = shake128, State}, In) ->
	?WRAP_STATE(T, libdecaf:shake128_update(State, In));
update({T = shake256, State}, In) ->
	?WRAP_STATE(T, libdecaf:shake256_update(State, In));
update(State, In) ->
	erlang:error({badarg, [State, In]}).

final({sha3_224, State}) ->
	libdecaf:sha3_224_final(State);
final({sha3_256, State}) ->
	libdecaf:sha3_256_final(State);
final({sha3_384, State}) ->
	libdecaf:sha3_384_final(State);
final({sha3_512, State}) ->
	libdecaf:sha3_512_final(State);
final(State) ->
	erlang:error({badarg, [State]}).

final({sha3_224, State}, Outlen) ->
	libdecaf:sha3_224_final(State, Outlen);
final({sha3_256, State}, Outlen) ->
	libdecaf:sha3_256_final(State, Outlen);
final({sha3_384, State}, Outlen) ->
	libdecaf:sha3_384_final(State, Outlen);
final({sha3_512, State}, Outlen) ->
	libdecaf:sha3_512_final(State, Outlen);
final({shake128, State}, Outlen) ->
	libdecaf:shake128_final(State, Outlen);
final({shake256, State}, Outlen) ->
	libdecaf:shake256_final(State, Outlen);
final(State, Outlen) ->
	erlang:error({badarg, [State, Outlen]}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
