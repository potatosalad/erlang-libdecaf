%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2018-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  27 November 2018 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libdecaf_nif).

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
	x25519/2
]).
%% decaf/point_448.h
-export([
	x448_derive_public_key/1,
	x448/2
]).
%% decaf/sha512.h
-export([
	sha2_512_hash/2,
	sha2_512_hash_init/0,
	sha2_512_hash_update/2,
	sha2_512_hash_final/2
]).
%%% Helpers: decaf/sha512.h
-export([
	sha2_512/2,
	sha2_512_init/0,
	sha2_512_update/2,
	sha2_512_final/2
]).
%% decaf/shake.h
% SHA-3 API
-export([
	sha3_224_hash/2,
	sha3_224_hash_init/0,
	sha3_224_hash_update/2,
	sha3_224_hash_final/2,
	sha3_256_hash/2,
	sha3_256_hash_init/0,
	sha3_256_hash_update/2,
	sha3_256_hash_final/2,
	sha3_384_hash/2,
	sha3_384_hash_init/0,
	sha3_384_hash_update/2,
	sha3_384_hash_final/2,
	sha3_512_hash/2,
	sha3_512_hash_init/0,
	sha3_512_hash_update/2,
	sha3_512_hash_final/2
]).
%%% Helpers: SHA-3 API
-export([
	sha3_224/2,
	sha3_224_init/0,
	sha3_224_update/2,
	sha3_224_final/2,
	sha3_256/2,
	sha3_256_init/0,
	sha3_256_update/2,
	sha3_256_final/2,
	sha3_384/2,
	sha3_384_init/0,
	sha3_384_update/2,
	sha3_384_final/2,
	sha3_512/2,
	sha3_512_init/0,
	sha3_512_update/2,
	sha3_512_final/2
]).
% KECCAK API
-export([
	keccak_224_hash/2,
	keccak_224_hash_init/0,
	keccak_224_hash_update/2,
	keccak_224_hash_final/2,
	keccak_256_hash/2,
	keccak_256_hash_init/0,
	keccak_256_hash_update/2,
	keccak_256_hash_final/2,
	keccak_384_hash/2,
	keccak_384_hash_init/0,
	keccak_384_hash_update/2,
	keccak_384_hash_final/2,
	keccak_512_hash/2,
	keccak_512_hash_init/0,
	keccak_512_hash_update/2,
	keccak_512_hash_final/2
]).
%%% Helpers: KECCAK API
-export([
	keccak_224/2,
	keccak_224_init/0,
	keccak_224_update/2,
	keccak_224_final/2,
	keccak_256/2,
	keccak_256_init/0,
	keccak_256_update/2,
	keccak_256_final/2,
	keccak_384/2,
	keccak_384_init/0,
	keccak_384_update/2,
	keccak_384_final/2,
	keccak_512/2,
	keccak_512_init/0,
	keccak_512_update/2,
	keccak_512_final/2
]).
% SHAKE API
-export([
	shake128_xof/2,
	shake128_xof_init/0,
	shake128_xof_update/2,
	shake128_xof_output/2,
	shake256_xof/2,
	shake256_xof_init/0,
	shake256_xof_update/2,
	shake256_xof_output/2
]).
%%% Helpers: SHAKE API
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
	spongerng_csprng_init_from_buffer/2,
	spongerng_csprng_init_from_file/3,
	spongerng_csprng_init_from_dev_urandom/0,
	spongerng_csprng_next/2,
	spongerng_csprng_stir/2
]).
%%% Helpers: decaf/spongerng.h
-export([
	spongerng_init_from_buffer/2,
	spongerng_init_from_file/3,
	spongerng_init_from_dev_urandom/0,
	spongerng_next/2,
	spongerng_stir/2
]).

-on_load(init/0).

%%%===================================================================
%%% decaf/ed255.h
%%%===================================================================

ed25519_derive_keypair(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_derive_public_key(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_keypair_extract_private_key(_Keypair) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_keypair_extract_public_key(_Keypair) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_keypair_sign(_Keypair, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_keypair_sign_prehash(_Keypair, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_sign(_Privkey, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_sign_prehash(_Privkey, _Pubkey, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_verify(_Signature, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_verify_prehash(_Signature, _Pubkey, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_convert_public_key_to_x25519(_Pubkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed25519_convert_private_key_to_x25519(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/ed448.h
%%%===================================================================

ed448_derive_keypair(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_derive_public_key(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_keypair_extract_private_key(_Keypair) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_keypair_extract_public_key(_Keypair) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_keypair_sign(_Keypair, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_keypair_sign_prehash(_Keypair, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_sign(_Privkey, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_sign_prehash(_Privkey, _Pubkey, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_verify(_Signature, _Pubkey, _Message, _Prehashed, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_verify_prehash(_Signature, _Pubkey, _Message, _Context) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_convert_public_key_to_x448(_Pubkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

ed448_convert_private_key_to_x448(_Privkey) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/point_255.h
%%%===================================================================

x25519_derive_public_key(_Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

x25519(_Base, _Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/point_448.h
%%%===================================================================

x448_derive_public_key(_Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

x448(_Base, _Scalar) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% decaf/sha512.h
%%%===================================================================

sha2_512_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha2_512_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha2_512_hash_update(_Ctx, _In) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha2_512_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha2_512(Input, OutputLen) ->
	sha2_512_hash(Input, OutputLen).

sha2_512_init() ->
	sha2_512_hash_init().

sha2_512_update(Ctx, Input) ->
	sha2_512_hash_update(Ctx, Input).

sha2_512_final(Ctx, OutputLen) ->
	sha2_512_hash_final(Ctx, OutputLen).

%%%===================================================================
%%% decaf/shake.h
%%%===================================================================

%% SHA-3 API functions

sha3_224_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_hash_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_hash_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_256_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_hash_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_384_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_hash_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_512_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

sha3_224(Input, OutputLen) ->
	sha3_224_hash(Input, OutputLen).

sha3_224_init() ->
	sha3_224_hash_init().

sha3_224_update(Ctx, Input) ->
	sha3_224_hash_update(Ctx, Input).

sha3_224_final(Ctx, OutputLen) ->
	sha3_224_hash_final(Ctx, OutputLen).

sha3_256(Input, OutputLen) ->
	sha3_256_hash(Input, OutputLen).

sha3_256_init() ->
	sha3_256_hash_init().

sha3_256_update(Ctx, Input) ->
	sha3_256_hash_update(Ctx, Input).

sha3_256_final(Ctx, OutputLen) ->
	sha3_256_hash_final(Ctx, OutputLen).

sha3_384(Input, OutputLen) ->
	sha3_384_hash(Input, OutputLen).

sha3_384_init() ->
	sha3_384_hash_init().

sha3_384_update(Ctx, Input) ->
	sha3_384_hash_update(Ctx, Input).

sha3_384_final(Ctx, OutputLen) ->
	sha3_384_hash_final(Ctx, OutputLen).

sha3_512(Input, OutputLen) ->
	sha3_512_hash(Input, OutputLen).

sha3_512_init() ->
	sha3_512_hash_init().

sha3_512_update(Ctx, Input) ->
	sha3_512_hash_update(Ctx, Input).

sha3_512_final(Ctx, OutputLen) ->
	sha3_512_hash_final(Ctx, OutputLen).

%% KECCAK API functions

keccak_224_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_224_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_224_hash_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_224_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_256_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_256_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_256_hash_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_256_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_384_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_384_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_384_hash_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_384_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_512_hash(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_512_hash_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_512_hash_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_512_hash_final(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

keccak_224(Input, OutputLen) ->
	keccak_224_hash(Input, OutputLen).

keccak_224_init() ->
	keccak_224_hash_init().

keccak_224_update(Ctx, Input) ->
	keccak_224_hash_update(Ctx, Input).

keccak_224_final(Ctx, OutputLen) ->
	keccak_224_hash_final(Ctx, OutputLen).

keccak_256(Input, OutputLen) ->
	keccak_256_hash(Input, OutputLen).

keccak_256_init() ->
	keccak_256_hash_init().

keccak_256_update(Ctx, Input) ->
	keccak_256_hash_update(Ctx, Input).

keccak_256_final(Ctx, OutputLen) ->
	keccak_256_hash_final(Ctx, OutputLen).

keccak_384(Input, OutputLen) ->
	keccak_384_hash(Input, OutputLen).

keccak_384_init() ->
	keccak_384_hash_init().

keccak_384_update(Ctx, Input) ->
	keccak_384_hash_update(Ctx, Input).

keccak_384_final(Ctx, OutputLen) ->
	keccak_384_hash_final(Ctx, OutputLen).

keccak_512(Input, OutputLen) ->
	keccak_512_hash(Input, OutputLen).

keccak_512_init() ->
	keccak_512_hash_init().

keccak_512_update(Ctx, Input) ->
	keccak_512_hash_update(Ctx, Input).

keccak_512_final(Ctx, OutputLen) ->
	keccak_512_hash_final(Ctx, OutputLen).

%% SHAKE API functions

shake128_xof(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_xof_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_xof_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128_xof_output(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_xof(_Input, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_xof_init() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_xof_update(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake256_xof_output(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

shake128(Input, OutputLen) ->
	shake128_xof(Input, OutputLen).

shake128_init() ->
	shake128_xof_init().

shake128_update(Ctx, Input) ->
	shake128_xof_update(Ctx, Input).

shake128_final(OldCtx, OutputLen) ->
	{_NewCtx, Output} = shake128_xof_output(OldCtx, OutputLen),
	Output.

shake256(Input, OutputLen) ->
	shake256_xof(Input, OutputLen).

shake256_init() ->
	shake256_xof_init().

shake256_update(Ctx, Input) ->
	shake256_xof_update(Ctx, Input).

shake256_final(OldCtx, OutputLen) ->
	{_NewCtx, Output} = shake256_xof_output(OldCtx, OutputLen),
	Output.

%%%===================================================================
%%% decaf/spongerng.h
%%%===================================================================

spongerng_csprng_init_from_buffer(_Input, _Deterministic) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_csprng_init_from_file(_File, _InputLen, _Deterministic) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_csprng_init_from_dev_urandom() ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_csprng_next(_Ctx, _OutputLen) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_csprng_stir(_Ctx, _Input) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

spongerng_init_from_buffer(Input, Deterministic) ->
	spongerng_csprng_init_from_buffer(Input, Deterministic).

spongerng_init_from_file(File, InputLen, Deterministic) ->
	spongerng_csprng_init_from_file(File, InputLen, Deterministic).

spongerng_init_from_dev_urandom() ->
	spongerng_csprng_init_from_dev_urandom().

spongerng_next(Ctx, OutputLen) ->
	spongerng_csprng_next(Ctx, OutputLen).

spongerng_stir(Ctx, Input) ->
	spongerng_csprng_stir(Ctx, Input).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
init() ->
	SoName = filename:join(libdecaf:priv_dir(), ?MODULE_STRING),
	erlang:load_nif(SoName, 0).
