%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  28 Aug 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libdecaf_keccak).

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

hash(keccak_224, In) ->
	libdecaf:keccak_224(In);
hash(keccak_256, In) ->
	libdecaf:keccak_256(In);
hash(keccak_384, In) ->
	libdecaf:keccak_384(In);
hash(keccak_512, In) ->
	libdecaf:keccak_512(In);
hash(Type, In) ->
	erlang:error({badarg, [Type, In]}).

hash(keccak_224, In, Outlen) ->
	libdecaf:keccak_224(In, Outlen);
hash(keccak_256, In, Outlen) ->
	libdecaf:keccak_256(In, Outlen);
hash(keccak_384, In, Outlen) ->
	libdecaf:keccak_384(In, Outlen);
hash(keccak_512, In, Outlen) ->
	libdecaf:keccak_512(In, Outlen);
hash(Type, In, Outlen) ->
	erlang:error({badarg, [Type, In, Outlen]}).

init(keccak_224) ->
	?WRAP_STATE(keccak_224, libdecaf:keccak_224_init());
init(keccak_256) ->
	?WRAP_STATE(keccak_256, libdecaf:keccak_256_init());
init(keccak_384) ->
	?WRAP_STATE(keccak_384, libdecaf:keccak_384_init());
init(keccak_512) ->
	?WRAP_STATE(keccak_512, libdecaf:keccak_512_init());
init(Type) ->
	erlang:error({badarg, [Type]}).

update({T = keccak_224, State}, In) ->
	?WRAP_STATE(T, libdecaf:keccak_224_update(State, In));
update({T = keccak_256, State}, In) ->
	?WRAP_STATE(T, libdecaf:keccak_256_update(State, In));
update({T = keccak_384, State}, In) ->
	?WRAP_STATE(T, libdecaf:keccak_384_update(State, In));
update({T = keccak_512, State}, In) ->
	?WRAP_STATE(T, libdecaf:keccak_512_update(State, In));
update(State, In) ->
	erlang:error({badarg, [State, In]}).

final({keccak_224, State}) ->
	libdecaf:keccak_224_final(State);
final({keccak_256, State}) ->
	libdecaf:keccak_256_final(State);
final({keccak_384, State}) ->
	libdecaf:keccak_384_final(State);
final({keccak_512, State}) ->
	libdecaf:keccak_512_final(State);
final(State) ->
	erlang:error({badarg, [State]}).

final({keccak_224, State}, Outlen) ->
	libdecaf:keccak_224_final(State, Outlen);
final({keccak_256, State}, Outlen) ->
	libdecaf:keccak_256_final(State, Outlen);
final({keccak_384, State}, Outlen) ->
	libdecaf:keccak_384_final(State, Outlen);
final({keccak_512, State}, Outlen) ->
	libdecaf:keccak_512_final(State, Outlen);
final(State, Outlen) ->
	erlang:error({badarg, [State, Outlen]}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
