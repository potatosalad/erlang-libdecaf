%% Streaming prehash EdDSA. States are immutable, like the hash APIs.
-module(libdecaf_eddsa).

-export([sign_init/2, sign_init/3, sign_update/2, sign_final/1]).
-export([verify_init/3, verify_init/4, verify_update/2, verify_final/1]).
-export_type([algorithm/0, sign_state/0, verify_state/0]).

-type algorithm() :: ed25519ph | ed448ph.
-type hash_state() :: {sha2_512 | shake256, reference()}.
-opaque sign_state() :: {libdecaf_sign, algorithm(), reference(), binary(), hash_state()}.
-opaque verify_state() :: {libdecaf_verify, algorithm(), binary(), binary(), binary(), hash_state()}.

-spec sign_init(algorithm(), reference()) -> sign_state().
sign_init(Algorithm, Keypair) ->
	sign_init(Algorithm, Keypair, <<>>).

-spec sign_init(algorithm(), reference(), binary()) -> sign_state().
sign_init(Algorithm, Keypair, Context)
		when (Algorithm =:= ed25519ph orelse Algorithm =:= ed448ph),
		is_reference(Keypair), is_binary(Context), byte_size(Context) =< 255 ->
	%% Validate the resource's curve before retaining it in the state.
	_ = public_key(Algorithm, Keypair),
	{libdecaf_sign, Algorithm, Keypair, Context, hash_init(Algorithm)};
sign_init(_, _, _) ->
	erlang:error(badarg).

-spec sign_update(sign_state(), iodata()) -> sign_state().
sign_update({libdecaf_sign, Algorithm, Keypair, Context, Hash}, Input) ->
	{libdecaf_sign, Algorithm, Keypair, Context, hash_update(Algorithm, Hash, Input)};
sign_update(_, _) ->
	erlang:error(badarg).

-spec sign_final(sign_state()) -> binary().
sign_final({libdecaf_sign, ed25519ph, Keypair, Context, Hash}) ->
	libdecaf:ed25519_keypair_sign(Keypair, hash_final(ed25519ph, Hash), 1, Context);
sign_final({libdecaf_sign, ed448ph, Keypair, Context, Hash}) ->
	libdecaf:ed448_keypair_sign(Keypair, hash_final(ed448ph, Hash), 1, Context);
sign_final(_) ->
	erlang:error(badarg).

-spec verify_init(algorithm(), binary(), binary()) -> verify_state().
verify_init(Algorithm, Signature, PublicKey) ->
	verify_init(Algorithm, Signature, PublicKey, <<>>).

-spec verify_init(algorithm(), binary(), binary(), binary()) -> verify_state().
verify_init(Algorithm, Signature, PublicKey, Context)
		when is_binary(Signature), is_binary(PublicKey),
		is_binary(Context), byte_size(Context) =< 255,
		((Algorithm =:= ed25519ph andalso byte_size(Signature) =:= 64 andalso byte_size(PublicKey) =:= 32)
		orelse (Algorithm =:= ed448ph andalso byte_size(Signature) =:= 114 andalso byte_size(PublicKey) =:= 57)) ->
	{libdecaf_verify, Algorithm, Signature, PublicKey, Context, hash_init(Algorithm)};
verify_init(_, _, _, _) ->
	erlang:error(badarg).

-spec verify_update(verify_state(), iodata()) -> verify_state().
verify_update({libdecaf_verify, Algorithm, Signature, PublicKey, Context, Hash}, Input) ->
	{libdecaf_verify, Algorithm, Signature, PublicKey, Context, hash_update(Algorithm, Hash, Input)};
verify_update(_, _) ->
	erlang:error(badarg).

-spec verify_final(verify_state()) -> boolean().
verify_final({libdecaf_verify, ed25519ph, Signature, PublicKey, Context, Hash}) ->
	libdecaf:ed25519_verify(Signature, PublicKey, hash_final(ed25519ph, Hash), 1, Context);
verify_final({libdecaf_verify, ed448ph, Signature, PublicKey, Context, Hash}) ->
	libdecaf:ed448_verify(Signature, PublicKey, hash_final(ed448ph, Hash), 1, Context);
verify_final(_) ->
	erlang:error(badarg).

public_key(ed25519ph, Keypair) -> libdecaf:ed25519_keypair_extract_public_key(Keypair);
public_key(ed448ph, Keypair) -> libdecaf:ed448_keypair_extract_public_key(Keypair).

hash_init(ed25519ph) -> libdecaf_sha2:init(sha2_512);
hash_init(ed448ph) -> libdecaf_sha3:init(shake256).

hash_update(ed25519ph, Hash, Input) -> libdecaf_sha2:update(Hash, Input);
hash_update(ed448ph, Hash, Input) -> libdecaf_sha3:update(Hash, Input).

hash_final(ed25519ph, Hash) -> libdecaf_sha2:final(Hash, 64);
hash_final(ed448ph, Hash) -> libdecaf_sha3:final(Hash, 64).
