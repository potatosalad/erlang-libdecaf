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
-module(libdecaf_sha2).

%% API
-export([hash/2]).
-export([hash/3]).
-export([init/1]).
-export([update/2]).
-export([final/1]).
-export([final/2]).

%% Macros
-define(SHA2_512_OUTPUT_BYTES, 64).

%%%===================================================================
%%% API functions
%%%===================================================================

hash(sha2_512, In) ->
	libdecaf:sha2_512(In, ?SHA2_512_OUTPUT_BYTES);
hash(Type, In) ->
	erlang:error({badarg, [Type, In]}).

hash(sha2_512, In, Outlen) ->
	libdecaf:sha2_512(In, Outlen);
hash(Type, In, Outlen) ->
	erlang:error({badarg, [Type, In, Outlen]}).

init(sha2_512) ->
	libdecaf:sha2_512_init();
init(Type) ->
	erlang:error({badarg, [Type]}).

update(State={sha2_512, _}, In) ->
	libdecaf:sha2_512_update(State, In);
update(State, In) ->
	erlang:error({badarg, [State, In]}).

final(State={sha2_512, _}) ->
	libdecaf:sha2_512_final(State, ?SHA2_512_OUTPUT_BYTES);
final(State) ->
	erlang:error({badarg, [State]}).

final(State={sha2_512, _}, Outlen) ->
	libdecaf:sha2_512_final(State, Outlen);
final(State, Outlen) ->
	erlang:error({badarg, [State, Outlen]}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
