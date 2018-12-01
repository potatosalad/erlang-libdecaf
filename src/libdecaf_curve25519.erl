%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2018, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  29 Feb 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libdecaf_curve25519).

%% API
% EdDSA
-export([eddsa_keypair/0]).
-export([eddsa_keypair/1]).
-export([eddsa_secret_to_pk/1]).
-export([eddsa_sk_to_pk/1]).
-export([eddsa_sk_to_secret/1]).
-export([eddsa_keypair_to_x25519_keypair/1]).
-export([eddsa_pk_to_x25519_pk/1]).
-export([eddsa_secret_to_x25519_keypair/1]).
-export([eddsa_secret_to_x25519_secret/1]).
-export([eddsa_sk_to_x25519_keypair/1]).
% Ed25519
-export([ed25519_sign/2]).
-export([ed25519_verify/3]).
% Ed25519ctx
-export([ed25519ctx_sign/2]).
-export([ed25519ctx_sign/3]).
-export([ed25519ctx_verify/3]).
-export([ed25519ctx_verify/4]).
% Ed25519ph
-export([ed25519ph_sign/2]).
-export([ed25519ph_sign/3]).
-export([ed25519ph_verify/3]).
-export([ed25519ph_verify/4]).
% X25519
-export([curve25519/1]).
-export([curve25519/2]).
-export([x25519/1]).
-export([x25519/2]).
-export([x25519_keypair/0]).
-export([x25519_keypair/1]).

%% Macro
% EdDSA
-define(EdDSA_SECRET_BYTES, 32).
-define(EdDSA_PK_BYTES,     32).
-define(EdDSA_SK_BYTES,     64).
-define(EdDSA_SIGN_BYTES,   64).
% X25519
-define(X25519_PRIVATE_BYTES, 32).
-define(X25519_PUBLIC_BYTES,  32).

%%%===================================================================
%%% API functions
%%%===================================================================

% EdDSA

eddsa_keypair() ->
	eddsa_keypair(crypto:strong_rand_bytes(?EdDSA_SECRET_BYTES)).

eddsa_keypair(Secret)
		when is_binary(Secret)
		andalso byte_size(Secret) =:= ?EdDSA_SECRET_BYTES ->
	PK = eddsa_secret_to_pk(Secret),
	{PK, << Secret/binary, PK/binary >>}.

eddsa_secret_to_pk(Secret)
		when is_binary(Secret)
		andalso byte_size(Secret) =:= ?EdDSA_SECRET_BYTES ->
	libdecaf:ed25519_derive_public_key(Secret).

eddsa_sk_to_pk(<< _:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary >>) ->
	PK.

eddsa_sk_to_secret(<< Secret:?EdDSA_SECRET_BYTES/binary, _:?EdDSA_PK_BYTES/binary >>) ->
	Secret.

eddsa_keypair_to_x25519_keypair({<< PK:?EdDSA_PK_BYTES/binary >>, SK = << _:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary >>}) ->
	eddsa_sk_to_x25519_keypair(SK).

eddsa_pk_to_x25519_pk(<< PK:?EdDSA_PK_BYTES/binary >>) ->
	libdecaf:ed25519_convert_public_key_to_x25519(PK).

eddsa_secret_to_x25519_keypair(<< Secret:?EdDSA_SECRET_BYTES/binary >>) ->
	x25519_keypair(eddsa_secret_to_x25519_secret(Secret)).

eddsa_secret_to_x25519_secret(<< Secret:?EdDSA_SECRET_BYTES/binary >>) ->
	libdecaf:ed25519_convert_private_key_to_x25519(Secret).

eddsa_sk_to_x25519_keypair(SK = << Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary >>) ->
	KP0 = {eddsa_pk_to_x25519_pk(PK), eddsa_secret_to_x25519_secret(Secret)},
	KP1 = eddsa_secret_to_x25519_keypair(Secret),
	case KP0 =:= KP1 of
		true ->
			KP1;
		false ->
			erlang:error({badarg, [SK]})
	end.

% Ed25519

ed25519_sign(M, << Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary >>) when is_binary(M) ->
	libdecaf:ed25519_sign(Secret, PK, M, 0, no_context).

ed25519_verify(<< Sig:?EdDSA_SIGN_BYTES/binary >>, M, << PK:?EdDSA_PK_BYTES/binary >>) when is_binary(M) ->
	libdecaf:ed25519_verify(Sig, PK, M, 0, no_context).

% Ed25519ctx

ed25519ctx_sign(M, << SK:?EdDSA_SK_BYTES/binary >>) when is_binary(M) ->
	ed25519ctx_sign(M, SK, <<>>).

ed25519ctx_sign(M, << Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary >>, C)
		when is_binary(M)
		andalso is_binary(C)
		andalso byte_size(C) =< 255 ->
	libdecaf:ed25519_sign(Secret, PK, M, 0, C).

ed25519ctx_verify(<< Sig:?EdDSA_SIGN_BYTES/binary >>, M, << PK:?EdDSA_PK_BYTES/binary >>) when is_binary(M) ->
	ed25519ctx_verify(Sig, M, PK, <<>>).

ed25519ctx_verify(<< Sig:?EdDSA_SIGN_BYTES/binary >>, M, << PK:?EdDSA_PK_BYTES/binary >>, C)
		when is_binary(M)
		andalso is_binary(C)
		andalso byte_size(C) =< 255 ->
	libdecaf:ed25519_verify(Sig, PK, M, 0, C).

% Ed25519ph

ed25519ph_sign(M, << SK:?EdDSA_SK_BYTES/binary >>) when is_binary(M) ->
	ed25519ph_sign(M, SK, <<>>).

ed25519ph_sign(M, << Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary >>, C)
		when is_binary(M)
		andalso is_binary(C)
		andalso byte_size(C) =< 255 ->
	libdecaf:ed25519_sign_prehash(Secret, PK, M, C).

ed25519ph_verify(<< Sig:?EdDSA_SIGN_BYTES/binary >>, M, << PK:?EdDSA_PK_BYTES/binary >>) when is_binary(M) ->
	ed25519ph_verify(Sig, M, PK, <<>>).

ed25519ph_verify(<< Sig:?EdDSA_SIGN_BYTES/binary >>, M, << PK:?EdDSA_PK_BYTES/binary >>, C)
		when is_binary(M)
		andalso is_binary(C)
		andalso byte_size(C) =< 255 ->
	libdecaf:ed25519_verify_prehash(Sig, PK, M, C).

% X25519

curve25519(Scalar) when is_integer(Scalar) ->
	curve25519(<< Scalar:?X25519_PRIVATE_BYTES/unsigned-little-integer-unit:8 >>);
curve25519(Scalar)
		when is_binary(Scalar)
		andalso byte_size(Scalar) =:= ?X25519_PRIVATE_BYTES ->
	<< U:?X25519_PUBLIC_BYTES/unsigned-little-integer-unit:8 >> = libdecaf:x25519_derive_public_key(Scalar),
	U.

curve25519(Scalar, Base) when is_integer(Scalar) ->
	curve25519(<< Scalar:?X25519_PRIVATE_BYTES/unsigned-little-integer-unit:8 >>, Base);
curve25519(Scalar, Base) when is_integer(Base) ->
	curve25519(Scalar, << Base:?X25519_PUBLIC_BYTES/unsigned-little-integer-unit:8 >>);
curve25519(Scalar, Base)
		when is_binary(Scalar)
		andalso byte_size(Scalar) =:= ?X25519_PRIVATE_BYTES
		andalso is_binary(Base)
		andalso byte_size(Base) =:= ?X25519_PUBLIC_BYTES ->
	<< U:?X25519_PUBLIC_BYTES/unsigned-little-integer-unit:8 >> = libdecaf:x25519(Base, Scalar),
	U.

x25519(K)
		when is_binary(K)
		andalso byte_size(K) =:= ?X25519_PRIVATE_BYTES ->
	libdecaf:x25519_derive_public_key(K).

x25519(K, U)
		when is_binary(K)
		andalso byte_size(K) =:= ?X25519_PRIVATE_BYTES
		andalso is_binary(U)
		andalso byte_size(U) =:= ?X25519_PUBLIC_BYTES ->
	libdecaf:x25519(U, K).

x25519_keypair() ->
	x25519_keypair(crypto:strong_rand_bytes(?X25519_PRIVATE_BYTES)).

x25519_keypair(Secret)
		when is_binary(Secret)
		andalso byte_size(Secret) =:= ?X25519_PRIVATE_BYTES ->
	{x25519(Secret), Secret}.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
