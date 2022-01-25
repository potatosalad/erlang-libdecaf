%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  30 Nov 2018 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libdecaf_spongerng).

%% API
-export([init_from_buffer/2]).
-export([init_from_file/3]).
-export([init_from_dev_urandom/0]).
-export([next/2]).
-export([stir/2]).

%% Macros
-define(WRAP_STATE(T, R),
	case R of
		{NewState, Result} when is_reference(NewState) ->
			{{T, NewState}, Result};
		NewState when is_reference(NewState) ->
			{T, NewState};
		Other ->
			Other
	end).

%%%===================================================================
%%% API functions
%%%===================================================================

init_from_buffer(In, Deterministic) when is_boolean(Deterministic) ->
	?WRAP_STATE(spongerng, libdecaf:spongerng_init_from_buffer(In, Deterministic)).

init_from_file(Filename, Inlen, Deterministic) when is_boolean(Deterministic) ->
	?WRAP_STATE(spongerng, libdecaf:spongerng_init_from_file(Filename, Inlen, Deterministic)).

init_from_dev_urandom() ->
	?WRAP_STATE(spongerng, libdecaf:spongerng_init_from_dev_urandom()).

next({spongerng, State}, Outlen) ->
	?WRAP_STATE(spongerng, libdecaf:spongerng_next(State, Outlen)).

stir({spongerng, State}, In) ->
	?WRAP_STATE(spongerng, libdecaf:spongerng_stir(State, In)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
