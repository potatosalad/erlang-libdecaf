%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  29 Feb 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(libdecaf_sha3).

%% API
-export([hash/2]).
-export([hash/3]).
-export([init/1]).
-export([update/2]).
-export([final/1]).
-export([final/2]).

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

hash(shake128, In, Outlen) ->
	libdecaf:shake128(In, Outlen);
hash(shake256, In, Outlen) ->
	libdecaf:shake256(In, Outlen);
hash(Type, In, Outlen) ->
	erlang:error({badarg, [Type, In, Outlen]}).

init(sha3_224) ->
	libdecaf:sha3_224_init();
init(sha3_256) ->
	libdecaf:sha3_256_init();
init(sha3_384) ->
	libdecaf:sha3_384_init();
init(sha3_512) ->
	libdecaf:sha3_512_init();
init(shake128) ->
	libdecaf:shake128_init();
init(shake256) ->
	libdecaf:shake256_init();
init(Type) ->
	erlang:error({badarg, [Type]}).

update(State={sha3_224, _}, In) ->
	libdecaf:sha3_224_update(State, In);
update(State={sha3_256, _}, In) ->
	libdecaf:sha3_256_update(State, In);
update(State={sha3_384, _}, In) ->
	libdecaf:sha3_384_update(State, In);
update(State={sha3_512, _}, In) ->
	libdecaf:sha3_512_update(State, In);
update(State={shake128, _}, In) ->
	libdecaf:shake128_update(State, In);
update(State={shake256, _}, In) ->
	libdecaf:shake256_update(State, In);
update(State, In) ->
	erlang:error({badarg, [State, In]}).

final(State={sha3_224, _}) ->
	libdecaf:sha3_224_final(State);
final(State={sha3_256, _}) ->
	libdecaf:sha3_256_final(State);
final(State={sha3_384, _}) ->
	libdecaf:sha3_384_final(State);
final(State={sha3_512, _}) ->
	libdecaf:sha3_512_final(State);
final(State) ->
	erlang:error({badarg, [State]}).

final(State={shake128, _}, Outlen) ->
	libdecaf:shake128_final(State, Outlen);
final(State={shake256, _}, Outlen) ->
	libdecaf:shake256_final(State, Outlen);
final(State, Outlen) ->
	erlang:error({badarg, [State, Outlen]}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
