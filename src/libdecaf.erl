%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Feb 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(libdecaf).

%% API
-export([start/0]).
% decaf/point_255.h
-export([x25519_generate_key/1]).
-export([x25519/2]).
% decaf/point_448.h
-export([x448_generate_key/1]).
-export([x448/2]).
% decaf/ed255.h
-export([ed25519_derive_public_key/1]).
-export([ed25519_sign/5]).
-export([ed25519_sign_prehash/4]).
-export([ed25519_verify/5]).
-export([ed25519_verify_prehash/4]).
% decaf/ed448.h
-export([ed448_derive_public_key/1]).
-export([ed448_sign/5]).
-export([ed448_sign_prehash/4]).
-export([ed448_verify/5]).
-export([ed448_verify_prehash/4]).
% decaf/sha512.h
-export([sha2_512/2]).
-export([sha2_512_init/0]).
-export([sha2_512_update/2]).
-export([sha2_512_final/2]).
% decaf/shake.h
%% SHA-3 API
-export([sha3_224/1]).
-export([sha3_224_init/0]).
-export([sha3_224_update/2]).
-export([sha3_224_final/1]).
-export([sha3_256/1]).
-export([sha3_256_init/0]).
-export([sha3_256_update/2]).
-export([sha3_256_final/1]).
-export([sha3_384/1]).
-export([sha3_384_init/0]).
-export([sha3_384_update/2]).
-export([sha3_384_final/1]).
-export([sha3_512/1]).
-export([sha3_512_init/0]).
-export([sha3_512_update/2]).
-export([sha3_512_final/1]).
%% SHAKE API
-export([shake128/2]).
-export([shake128_init/0]).
-export([shake128_update/2]).
-export([shake128_final/2]).
-export([shake256/2]).
-export([shake256_init/0]).
-export([shake256_update/2]).
-export([shake256_final/2]).

-on_load(init/0).

%%%===================================================================
%%% API functions
%%%===================================================================

start() ->
	application:ensure_all_started(?MODULE).

%%%===================================================================
%%% decaf/ed255.h
%%%===================================================================

ed25519_derive_public_key(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_sign(_Privkey, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_sign_prehash(_Privkey, _Pubkey, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_verify(_Signature, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_verify_prehash(_Signature, _Pubkey, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/ed448.h
%%%===================================================================

ed448_derive_public_key(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_sign(_Privkey, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_sign_prehash(_Privkey, _Pubkey, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_verify(_Signature, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_verify_prehash(_Signature, _Pubkey, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/point_255.h
%%%===================================================================

x25519_generate_key(_Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

x25519(_Base, _Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/point_448.h
%%%===================================================================

x448_generate_key(_Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

x448(_Base, _Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/sha512.h
%%%===================================================================

sha2_512(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha2_512_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha2_512_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha2_512_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/shake.h
%%%===================================================================

%% SHA-3 API functions

sha3_224(_In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_final(_State) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256(_In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_final(_State) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384(_In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_final(_State) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512(_In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_final(_State) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%% SHAKE API functions

shake128(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256(_In, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_update(_State, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_final(_State, _Outlen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
init() ->
	SoName = filename:join(priv_dir(), ?MODULE_STRING),
	erlang:load_nif(SoName, 0).

%% @private
priv_dir() ->
	case code:priv_dir(?MODULE) of
		{error, bad_name} ->
			case code:which(?MODULE) of
				Filename when is_list(Filename) ->
					filename:join([filename:dirname(Filename), "../priv"]);
				_ ->
					"../priv"
			end;
		Dir ->
			Dir
	end.
