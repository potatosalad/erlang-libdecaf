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
% decaf/decaf_255.h
-export([decaf_x25519_base_scalarmul/1]).
-export([decaf_x25519_direct_scalarmul/2]).
% decaf/decaf_448.h
-export([decaf_x448_base_scalarmul/1]).
-export([decaf_x448_direct_scalarmul/2]).
% decaf/eddsa_255.h
-export([decaf_255_eddsa_derive_public_key/1]).
-export([decaf_255_eddsa_sign/4]).
-export([decaf_255_eddsa_verify/4]).
% decaf/eddsa_448.h
-export([decaf_448_eddsa_derive_public_key/1]).
-export([decaf_448_eddsa_sign/5]).
-export([decaf_448_eddsa_verify/5]).
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
%%% decaf/decaf_255.h
%%%===================================================================

decaf_x25519_base_scalarmul(_Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

decaf_x25519_direct_scalarmul(_Base, _Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/decaf_448.h
%%%===================================================================

decaf_x448_base_scalarmul(_Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

decaf_x448_direct_scalarmul(_Base, _Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/eddsa_255.h
%%%===================================================================

decaf_255_eddsa_derive_public_key(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

decaf_255_eddsa_sign(_Privkey, _Pubkey, _Message, _Prehashed) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

decaf_255_eddsa_verify(_Signature, _Pubkey, _Message, _Prehashed) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/eddsa_448.h
%%%===================================================================

decaf_448_eddsa_derive_public_key(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

decaf_448_eddsa_sign(_Privkey, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

decaf_448_eddsa_verify(_Signature, _Pubkey, _Message, _Prehashed, _Context) ->
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
