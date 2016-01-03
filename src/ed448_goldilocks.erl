%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Jan 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(ed448_goldilocks).

-define(NAMESPACE, goldilocks).

%% API
-export([keygen/0]).
-export([derive_private_key/1]).
-export([underive_private_key/1]).
-export([private_to_public/1]).
-export([shared_secret/2]).
-export([sign/2]).
-export([verify/3]).

%%%===================================================================
%%% API
%%%===================================================================

keygen() ->
	call(keygen).

derive_private_key(Proto)
		when is_binary(Proto) ->
	call(derive_private_key, {Proto}).

underive_private_key(Privkey)
		when is_binary(Privkey) ->
	call(underive_private_key, {Privkey}).

private_to_public(Privkey)
		when is_binary(Privkey) ->
	call(private_to_public, {Privkey}).

shared_secret(MyPrivkey, YourPubkey)
		when is_binary(MyPrivkey)
		andalso is_binary(YourPubkey) ->
	call(shared_secret, {MyPrivkey, YourPubkey}).

sign(Message, Privkey)
		when is_binary(Message)
		andalso is_binary(Privkey) ->
	call(sign, {Message, Privkey}).

verify(Signature, Message, Pubkey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso is_binary(Pubkey) ->
	call(verify, {Signature, Message, Pubkey}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	ed448:call(?NAMESPACE, Function, Arguments).
