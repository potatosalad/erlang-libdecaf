%%% % @format
-module(libdecaf_curve448).
-moduledoc """
Keypair helpers, Ed448 signatures, and X448 key agreement.

Supports Ed448, Ed448ph, streaming prehash signatures,
and conversion between Ed448 and X448 key material.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2016-02-29", modified => "2026-10-22"}.
-moduledoc #{copyright => "Andrew Bennett"}.

%% API
% Keypair
-export([
    keypair_random/0,
    keypair_derive/1,
    keypair_extract_private_key/1,
    keypair_extract_public_key/1
]).
% EdDSA
-export([
    eddsa_keypair/0,
    eddsa_keypair/1,
    eddsa_secret_to_pk/1,
    eddsa_sk_to_pk/1,
    eddsa_sk_to_secret/1,
    eddsa_keypair_to_x448_keypair/1,
    eddsa_pk_to_x448_pk/1,
    eddsa_secret_to_x448_keypair/1,
    eddsa_secret_to_x448_secret/1,
    eddsa_sk_to_x448_keypair/1
]).
% Ed448
-export([
    ed448_keypair_sign/2,
    ed448_keypair_sign/3,
    ed448_sign/2,
    ed448_sign/3,
    ed448_verify/3,
    ed448_verify/4
]).
% Ed448ph
-export([
    ed448ph_keypair_sign/2,
    ed448ph_keypair_sign/3,
    ed448ph_sign/2,
    ed448ph_sign/3,
    ed448ph_verify/3,
    ed448ph_verify/4
]).
% X448
-export([
    curve448/1,
    curve448/2,
    x448/1,
    x448/2,
    x448_keypair/0,
    x448_keypair/1
]).

%% Streaming prehash EdDSA
-export([
    ed448ph_keypair_sign_init/1, ed448ph_keypair_sign_init/2,
    ed448ph_sign_init/1, ed448ph_sign_init/2,
    ed448ph_sign_update/2,
    ed448ph_sign_final/1,
    ed448ph_verify_init/2, ed448ph_verify_init/3,
    ed448ph_verify_update/2,
    ed448ph_verify_final/1
]).

%% Macro
% EdDSA
-define(EdDSA_SECRET_BYTES, 57).
-define(EdDSA_PK_BYTES, 57).
-define(EdDSA_SK_BYTES, 114).
-define(EdDSA_SIGN_BYTES, 114).
% X448
-define(X448_PRIVATE_BYTES, 56).
-define(X448_PUBLIC_BYTES, 56).

%%%===================================================================
%%% API functions
%%%===================================================================

% Keypair

keypair_random() ->
    keypair_derive(crypto:strong_rand_bytes(?EdDSA_SECRET_BYTES)).

keypair_derive(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?EdDSA_SECRET_BYTES
->
    libdecaf_nif:ed448_derive_keypair(Secret).

keypair_extract_private_key(Keypair) when is_reference(Keypair) ->
    libdecaf_nif:ed448_keypair_extract_private_key(Keypair).

keypair_extract_public_key(Keypair) when is_reference(Keypair) ->
    libdecaf_nif:ed448_keypair_extract_public_key(Keypair).

% EdDSA

eddsa_keypair() ->
    eddsa_keypair(crypto:strong_rand_bytes(?EdDSA_SECRET_BYTES)).

eddsa_keypair(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?EdDSA_SECRET_BYTES
->
    PK = eddsa_secret_to_pk(Secret),
    {PK, <<Secret/binary, PK/binary>>}.

eddsa_secret_to_pk(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?EdDSA_SECRET_BYTES
->
    libdecaf_nif:ed448_derive_public_key(Secret).

eddsa_sk_to_pk(<<_:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>) ->
    PK.

eddsa_sk_to_secret(<<Secret:?EdDSA_SECRET_BYTES/binary, _:?EdDSA_PK_BYTES/binary>>) ->
    Secret.

eddsa_keypair_to_x448_keypair({
    <<PK:?EdDSA_PK_BYTES/binary>>, SK = <<_:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>
}) ->
    eddsa_sk_to_x448_keypair(SK).

eddsa_pk_to_x448_pk(<<PK:?EdDSA_PK_BYTES/binary>>) ->
    libdecaf_nif:ed448_convert_public_key_to_x448(PK).

eddsa_secret_to_x448_keypair(<<Secret:?EdDSA_SECRET_BYTES/binary>>) ->
    x448_keypair(eddsa_secret_to_x448_secret(Secret)).

eddsa_secret_to_x448_secret(<<Secret:?EdDSA_SECRET_BYTES/binary>>) ->
    libdecaf_nif:ed448_convert_private_key_to_x448(Secret).

eddsa_sk_to_x448_keypair(SK = <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>) ->
    KP0 = {eddsa_pk_to_x448_pk(PK), eddsa_secret_to_x448_secret(Secret)},
    KP1 = eddsa_secret_to_x448_keypair(Secret),
    case KP0 =:= KP1 of
        true ->
            KP1;
        false ->
            erlang:error({badarg, [SK]})
    end.

% Ed448

ed448_keypair_sign(M, Keypair) when
    is_binary(M) andalso
        is_reference(Keypair)
->
    ed448_keypair_sign(M, Keypair, <<>>).

ed448_keypair_sign(M, Keypair, C) when
    is_binary(M) andalso
        is_reference(Keypair) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_keypair_sign(Keypair, M, 0, C).

ed448_sign(M, <<SK:?EdDSA_SK_BYTES/binary>>) when is_binary(M) ->
    ed448_sign(M, SK, <<>>).

ed448_sign(M, <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_sign(Secret, PK, M, 0, C).

ed448_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>) when is_binary(M) ->
    ed448_verify(Sig, M, PK, <<>>).

ed448_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_verify(Sig, PK, M, 0, C).

% Ed448ph

ed448ph_keypair_sign(M, Keypair) when
    is_binary(M) andalso
        is_reference(Keypair)
->
    ed448ph_keypair_sign(M, Keypair, <<>>).

ed448ph_keypair_sign(M, Keypair, C) when
    is_binary(M) andalso
        is_reference(Keypair) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_keypair_sign_prehash(Keypair, M, C).

ed448ph_sign(M, <<SK:?EdDSA_SK_BYTES/binary>>) when is_binary(M) ->
    ed448ph_sign(M, SK, <<>>).

ed448ph_sign(M, <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_sign_prehash(Secret, PK, M, C).

ed448ph_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>) when is_binary(M) ->
    ed448ph_verify(Sig, M, PK, <<>>).

ed448ph_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_verify_prehash(Sig, PK, M, C).

% X448

curve448(Scalar) when is_integer(Scalar) ->
    curve448(<<Scalar:?X448_PRIVATE_BYTES/unsigned-little-integer-unit:8>>);
curve448(Scalar) when
    is_binary(Scalar) andalso
        byte_size(Scalar) =:= ?X448_PRIVATE_BYTES
->
    <<U:?X448_PUBLIC_BYTES/unsigned-little-integer-unit:8>> = libdecaf_nif:x448_derive_public_key(Scalar),
    U.

curve448(Scalar, Base) when is_integer(Scalar) ->
    curve448(<<Scalar:?X448_PRIVATE_BYTES/unsigned-little-integer-unit:8>>, Base);
curve448(Scalar, Base) when is_integer(Base) ->
    curve448(Scalar, <<Base:?X448_PUBLIC_BYTES/unsigned-little-integer-unit:8>>);
curve448(Scalar, Base) when
    is_binary(Scalar) andalso
        byte_size(Scalar) =:= ?X448_PRIVATE_BYTES andalso
        is_binary(Base) andalso
        byte_size(Base) =:= ?X448_PUBLIC_BYTES
->
    <<U:?X448_PUBLIC_BYTES/unsigned-little-integer-unit:8>> = libdecaf_nif:x448(Base, Scalar),
    U.

x448(K) when
    is_binary(K) andalso
        byte_size(K) =:= ?X448_PRIVATE_BYTES
->
    libdecaf_nif:x448_derive_public_key(K).

x448(K, U) when
    is_binary(K) andalso
        byte_size(K) =:= ?X448_PRIVATE_BYTES andalso
        is_binary(U) andalso
        byte_size(U) =:= ?X448_PUBLIC_BYTES
->
    libdecaf_nif:x448(U, K).

x448_keypair() ->
    x448_keypair(crypto:strong_rand_bytes(?X448_PRIVATE_BYTES)).

x448_keypair(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?X448_PRIVATE_BYTES
->
    {x448(Secret), Secret}.

%%%===================================================================
%%% Streaming prehash signatures
%%%===================================================================

ed448ph_keypair_sign_init(Keypair) ->
    libdecaf_nif:ed448ph_keypair_sign_init(Keypair).

ed448ph_keypair_sign_init(Keypair, Context) ->
    libdecaf_nif:ed448ph_keypair_sign_init(Keypair, Context).

ed448ph_sign_init(SigningKey) ->
    libdecaf_nif:ed448ph_sign_init(SigningKey).

ed448ph_sign_init(SigningKey, Context) ->
    libdecaf_nif:ed448ph_sign_init(SigningKey, Context).

ed448ph_sign_update(State, Input) ->
    libdecaf_nif:ed448ph_sign_update(State, Input).

ed448ph_sign_final(State) ->
    libdecaf_nif:ed448ph_sign_final(State).

ed448ph_verify_init(Signature, PublicKey) ->
    libdecaf_nif:ed448ph_verify_init(Signature, PublicKey).

ed448ph_verify_init(Signature, PublicKey, Context) ->
    libdecaf_nif:ed448ph_verify_init(Signature, PublicKey, Context).

ed448ph_verify_update(State, Input) ->
    libdecaf_nif:ed448ph_verify_update(State, Input).

ed448ph_verify_final(State) ->
    libdecaf_nif:ed448ph_verify_final(State).
