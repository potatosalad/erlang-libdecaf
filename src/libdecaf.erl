%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Feb 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libdecaf).

%% API
-export([start/0]).
%% decaf/ed255.h
-export([
	ed25519_derive_keypair/1,
	ed25519_derive_public_key/1,
	ed25519_keypair_extract_private_key/1,
	ed25519_keypair_extract_public_key/1,
	ed25519_keypair_sign/4,
	ed25519_keypair_sign_prehash/3,
	ed25519_sign/5,
	ed25519_sign_prehash/4,
	ed25519_verify/5,
	ed25519_verify_prehash/4,
	ed25519_convert_public_key_to_x25519/1,
	ed25519_convert_private_key_to_x25519/1
]).
%% decaf/ed448.h
-export([
	ed448_derive_keypair/1,
	ed448_derive_public_key/1,
	ed448_keypair_extract_private_key/1,
	ed448_keypair_extract_public_key/1,
	ed448_keypair_sign/4,
	ed448_keypair_sign_prehash/3,
	ed448_sign/5,
	ed448_sign_prehash/4,
	ed448_verify/5,
	ed448_verify_prehash/4,
	ed448_convert_public_key_to_x448/1,
	ed448_convert_private_key_to_x448/1
]).
%% decaf/point_255.h
-export([
	x25519_derive_public_key/1,
	x25519_generate_key/1,
	x25519/2
]).
%% decaf/point_448.h
-export([
	x448_derive_public_key/1,
	x448_generate_key/1,
	x448/2
]).
%% decaf/sha512.h
-export([
	sha2_512/1,
	sha2_512/2,
	sha2_512_init/0,
	sha2_512_update/2,
	sha2_512_final/1,
	sha2_512_final/2
]).
%% decaf/shake.h
% SHA-3 API
-export([
	sha3_224/1,
	sha3_224/2,
	sha3_224_init/0,
	sha3_224_update/2,
	sha3_224_final/1,
	sha3_224_final/2,
	sha3_256/1,
	sha3_256/2,
	sha3_256_init/0,
	sha3_256_update/2,
	sha3_256_final/1,
	sha3_256_final/2,
	sha3_384/1,
	sha3_384/2,
	sha3_384_init/0,
	sha3_384_update/2,
	sha3_384_final/1,
	sha3_384_final/2,
	sha3_512/1,
	sha3_512/2,
	sha3_512_init/0,
	sha3_512_update/2,
	sha3_512_final/1,
	sha3_512_final/2
]).
% KECCAK API
-export([
	keccak_224/1,
	keccak_224/2,
	keccak_224_init/0,
	keccak_224_update/2,
	keccak_224_final/1,
	keccak_224_final/2,
	keccak_256/1,
	keccak_256/2,
	keccak_256_init/0,
	keccak_256_update/2,
	keccak_256_final/1,
	keccak_256_final/2,
	keccak_384/1,
	keccak_384/2,
	keccak_384_init/0,
	keccak_384_update/2,
	keccak_384_final/1,
	keccak_384_final/2,
	keccak_512/1,
	keccak_512/2,
	keccak_512_init/0,
	keccak_512_update/2,
	keccak_512_final/1,
	keccak_512_final/2
]).
% SHAKE API
-export([
	shake128/2,
	shake128_init/0,
	shake128_update/2,
	shake128_final/2,
	shake256/2,
	shake256_init/0,
	shake256_update/2,
	shake256_final/2
]).
%% decaf/spongerng.h
-export([
	spongerng_init_from_buffer/2,
	spongerng_init_from_file/3,
	spongerng_init_from_dev_urandom/0,
	spongerng_next/2,
	spongerng_stir/2
]).
%% Internal API
-export([priv_dir/0]).

%%%===================================================================
%%% API functions
%%%===================================================================

start() ->
	application:ensure_all_started(?MODULE).

%%%===================================================================
%%% decaf/ed255.h
%%%===================================================================

ed25519_derive_keypair(Privkey) ->
	libdecaf_nif:ed25519_derive_keypair(Privkey).

ed25519_derive_public_key(Privkey) ->
	libdecaf_nif:ed25519_derive_public_key(Privkey).

ed25519_keypair_extract_private_key(Keypair) ->
	libdecaf_nif:ed25519_keypair_extract_private_key(Keypair).

ed25519_keypair_extract_public_key(Keypair) ->
	libdecaf_nif:ed25519_keypair_extract_public_key(Keypair).

ed25519_keypair_sign(Keypair, Message, Prehashed, Context) ->
	libdecaf_nif:ed25519_keypair_sign(Keypair, Message, Prehashed, Context).

ed25519_keypair_sign_prehash(Keypair, Message, Context) ->
	libdecaf_nif:ed25519_keypair_sign_prehash(Keypair, Message, Context).

ed25519_sign(Privkey, Pubkey, Message, Prehashed, Context) ->
	libdecaf_nif:ed25519_sign(Privkey, Pubkey, Message, Prehashed, Context).

ed25519_sign_prehash(Privkey, Pubkey, Message, Context) ->
	libdecaf_nif:ed25519_sign_prehash(Privkey, Pubkey, Message, Context).

ed25519_verify(Signature, Pubkey, Message, Prehashed, Context) ->
	libdecaf_nif:ed25519_verify(Signature, Pubkey, Message, Prehashed, Context).

ed25519_verify_prehash(Signature, Pubkey, Message, Context) ->
	libdecaf_nif:ed25519_verify_prehash(Signature, Pubkey, Message, Context).

ed25519_convert_public_key_to_x25519(Pubkey) ->
	libdecaf_nif:ed25519_convert_public_key_to_x25519(Pubkey).

ed25519_convert_private_key_to_x25519(Privkey) ->
	libdecaf_nif:ed25519_convert_private_key_to_x25519(Privkey).

%%%===================================================================
%%% decaf/ed448.h
%%%===================================================================

ed448_derive_keypair(Privkey) ->
	libdecaf_nif:ed448_derive_keypair(Privkey).

ed448_derive_public_key(Privkey) ->
	libdecaf_nif:ed448_derive_public_key(Privkey).

ed448_keypair_extract_private_key(Keypair) ->
	libdecaf_nif:ed448_keypair_extract_private_key(Keypair).

ed448_keypair_extract_public_key(Keypair) ->
	libdecaf_nif:ed448_keypair_extract_public_key(Keypair).

ed448_keypair_sign(Keypair, Message, Prehashed, Context) ->
	libdecaf_nif:ed448_keypair_sign(Keypair, Message, Prehashed, Context).

ed448_keypair_sign_prehash(Keypair, Message, Context) ->
	libdecaf_nif:ed448_keypair_sign_prehash(Keypair, Message, Context).

ed448_sign(Privkey, Pubkey, Message, Prehashed, Context) ->
	libdecaf_nif:ed448_sign(Privkey, Pubkey, Message, Prehashed, Context).

ed448_sign_prehash(Privkey, Pubkey, Message, Context) ->
	libdecaf_nif:ed448_sign_prehash(Privkey, Pubkey, Message, Context).

ed448_verify(Signature, Pubkey, Message, Prehashed, Context) ->
	libdecaf_nif:ed448_verify(Signature, Pubkey, Message, Prehashed, Context).

ed448_verify_prehash(Signature, Pubkey, Message, Context) ->
	libdecaf_nif:ed448_verify_prehash(Signature, Pubkey, Message, Context).

ed448_convert_public_key_to_x448(Pubkey) ->
	libdecaf_nif:ed448_convert_public_key_to_x448(Pubkey).

ed448_convert_private_key_to_x448(Privkey) ->
	libdecaf_nif:ed448_convert_private_key_to_x448(Privkey).

%%%===================================================================
%%% decaf/point_255.h
%%%===================================================================

x25519_derive_public_key(Scalar) ->
	libdecaf_nif:x25519_derive_public_key(Scalar).

%% @deprecated Please use the function {@link libdecaf:x25519_derive_public_key/1} instead.
x25519_generate_key(Scalar) ->
	x25519_derive_public_key(Scalar).

x25519(Base, Scalar) ->
	libdecaf_nif:x25519(Base, Scalar).

%%%===================================================================
%%% decaf/point_448.h
%%%===================================================================

x448_derive_public_key(Scalar) ->
	libdecaf_nif:x448_derive_public_key(Scalar).

%% @deprecated Please use the function {@link libdecaf:x448_derive_public_key/1} instead.
x448_generate_key(Scalar) ->
	x448_derive_public_key(Scalar).

x448(Base, Scalar) ->
	libdecaf_nif:x448(Base, Scalar).

%%%===================================================================
%%% decaf/sha512.h
%%%===================================================================

sha2_512(In) ->
	sha2_512(In, 64).

sha2_512(In, Outlen) ->
	libdecaf_nif:sha2_512(In, Outlen).

sha2_512_init() ->
	libdecaf_nif:sha2_512_init().

sha2_512_update(State, In) ->
	libdecaf_nif:sha2_512_update(State, In).

sha2_512_final(State) ->
	sha2_512_final(State, 64).

sha2_512_final(State, Outlen) ->
	libdecaf_nif:sha2_512_final(State, Outlen).

%%%===================================================================
%%% decaf/shake.h
%%%===================================================================

%% SHA-3 API functions

sha3_224(In) ->
	sha3_224(In, 28).

sha3_224(In, Outlen) ->
	libdecaf_nif:sha3_224(In, Outlen).

sha3_224_init() ->
	libdecaf_nif:sha3_224_init().

sha3_224_update(State, In) ->
	libdecaf_nif:sha3_224_update(State, In).

sha3_224_final(State) ->
	sha3_224_final(State, 28).

sha3_224_final(State, Outlen) ->
	libdecaf_nif:sha3_224_final(State, Outlen).

sha3_256(In) ->
	sha3_256(In, 32).

sha3_256(In, Outlen) ->
	libdecaf_nif:sha3_256(In, Outlen).

sha3_256_init() ->
	libdecaf_nif:sha3_256_init().

sha3_256_update(State, In) ->
	libdecaf_nif:sha3_256_update(State, In).

sha3_256_final(State) ->
	sha3_256_final(State, 32).

sha3_256_final(State, Outlen) ->
	libdecaf_nif:sha3_256_final(State, Outlen).

sha3_384(In) ->
	sha3_384(In, 48).

sha3_384(In, Outlen) ->
	libdecaf_nif:sha3_384(In, Outlen).

sha3_384_init() ->
	libdecaf_nif:sha3_384_init().

sha3_384_update(State, In) ->
	libdecaf_nif:sha3_384_update(State, In).

sha3_384_final(State) ->
	sha3_384_final(State, 48).

sha3_384_final(State, Outlen) ->
	libdecaf_nif:sha3_384_final(State, Outlen).

sha3_512(In) ->
	sha3_512(In, 64).

sha3_512(In, Outlen) ->
	libdecaf_nif:sha3_512(In, Outlen).

sha3_512_init() ->
	libdecaf_nif:sha3_512_init().

sha3_512_update(State, In) ->
	libdecaf_nif:sha3_512_update(State, In).

sha3_512_final(State) ->
	sha3_512_final(State, 64).

sha3_512_final(State, Outlen) ->
	libdecaf_nif:sha3_512_final(State, Outlen).

%% KECCAK API functions

keccak_224(In) ->
	keccak_224(In, 28).

keccak_224(In, Outlen) ->
	libdecaf_nif:keccak_224(In, Outlen).

keccak_224_init() ->
	libdecaf_nif:keccak_224_init().

keccak_224_update(State, In) ->
	libdecaf_nif:keccak_224_update(State, In).

keccak_224_final(State) ->
	keccak_224_final(State, 28).

keccak_224_final(State, Outlen) ->
	libdecaf_nif:keccak_224_final(State, Outlen).

keccak_256(In) ->
	keccak_256(In, 32).

keccak_256(In, Outlen) ->
	libdecaf_nif:keccak_256(In, Outlen).

keccak_256_init() ->
	libdecaf_nif:keccak_256_init().

keccak_256_update(State, In) ->
	libdecaf_nif:keccak_256_update(State, In).

keccak_256_final(State) ->
	keccak_256_final(State, 32).

keccak_256_final(State, Outlen) ->
	libdecaf_nif:keccak_256_final(State, Outlen).

keccak_384(In) ->
	keccak_384(In, 48).

keccak_384(In, Outlen) ->
	libdecaf_nif:keccak_384(In, Outlen).

keccak_384_init() ->
	libdecaf_nif:keccak_384_init().

keccak_384_update(State, In) ->
	libdecaf_nif:keccak_384_update(State, In).

keccak_384_final(State) ->
	keccak_384_final(State, 48).

keccak_384_final(State, Outlen) ->
	libdecaf_nif:keccak_384_final(State, Outlen).

keccak_512(In) ->
	keccak_512(In, 64).

keccak_512(In, Outlen) ->
	libdecaf_nif:keccak_512(In, Outlen).

keccak_512_init() ->
	libdecaf_nif:keccak_512_init().

keccak_512_update(State, In) ->
	libdecaf_nif:keccak_512_update(State, In).

keccak_512_final(State) ->
	keccak_512_final(State, 64).

keccak_512_final(State, Outlen) ->
	libdecaf_nif:keccak_512_final(State, Outlen).

%% SHAKE API functions

shake128(In, Outlen) ->
	libdecaf_nif:shake128(In, Outlen).

shake128_init() ->
	libdecaf_nif:shake128_init().

shake128_update(State, In) ->
	libdecaf_nif:shake128_update(State, In).

shake128_final(State, Outlen) ->
	libdecaf_nif:shake128_final(State, Outlen).

shake256(In, Outlen) ->
	libdecaf_nif:shake256(In, Outlen).

shake256_init() ->
	libdecaf_nif:shake256_init().

shake256_update(State, In) ->
	libdecaf_nif:shake256_update(State, In).

shake256_final(State, Outlen) ->
	libdecaf_nif:shake256_final(State, Outlen).

%%%===================================================================
%%% decaf/spongerng.h
%%%===================================================================

spongerng_init_from_buffer(In, Deterministic) ->
	libdecaf_nif:spongerng_init_from_buffer(In, Deterministic).

spongerng_init_from_file(File, Inlen, Deterministic) ->
	libdecaf_nif:spongerng_init_from_file(File, Inlen, Deterministic).

spongerng_init_from_dev_urandom() ->
	libdecaf_nif:spongerng_init_from_dev_urandom().

spongerng_next(State, Outlen) ->
	libdecaf_nif:spongerng_next(State, Outlen).

spongerng_stir(State, In) ->
	libdecaf_nif:spongerng_stir(State, In).

%%%===================================================================
%%% Internal API Functions
%%%===================================================================

-spec priv_dir() -> file:filename_all().
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

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
