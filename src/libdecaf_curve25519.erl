%%% % @format
-module(libdecaf_curve25519).
-moduledoc """
Ed25519 signatures, native streaming Ed25519ph, and X25519 key agreement.

`keypair_random/0` and `keypair_derive/1` return native keypair resources.
`keypair_extract_private_key/1` returns the 32-byte secret seed. In contrast,
`eddsa_keypair/0,1` returns `{PublicKey, SigningKey}`, where the 64-byte
signing key is `<<Seed/binary, PublicKey/binary>>`.

Sign and verify a binary message using a native keypair:

```erlang
Keypair = libdecaf_curve25519:keypair_random(),
PublicKey = libdecaf_curve25519:keypair_extract_public_key(Keypair),
Signature = libdecaf_curve25519:ed25519_keypair_sign(<<"message">>, Keypair),
true = libdecaf_curve25519:ed25519_verify(Signature, <<"message">>, PublicKey).
```

`ed25519ph` prehashes the original message using SHA-512. Do not prehash the message yourself.
Streaming prehash signing keeps the keypair, context, and prehash in native
resources and accepts iodata chunks:

```erlang
{PublicKey, SigningKey} = libdecaf_curve25519:eddsa_keypair(),
S0 = libdecaf_curve25519:ed25519ph_sign_init(SigningKey, <<"example">>),
S1 = libdecaf_curve25519:ed25519ph_sign_update(S0, [<<"first ">>, <<"chunk">>]),
S2 = libdecaf_curve25519:ed25519ph_sign_update(S1, <<"second chunk">>),
Signature = libdecaf_curve25519:ed25519ph_sign_final(S2),
V0 = libdecaf_curve25519:ed25519ph_verify_init(Signature, PublicKey, <<"example">>),
V1 = libdecaf_curve25519:ed25519ph_verify_update(V0, <<"first chunksecond chunk">>),
true = libdecaf_curve25519:ed25519ph_verify_final(V1).
```

Use `ed25519ph_keypair_sign_init/1,2` when you already have a native keypair.
Both initializers produce the same signing state. Each update returns a new
immutable state; finalization leaves its input reusable. Signing and verification
states are distinct, and states from the other curve are rejected. Large updates
yield to the scheduler, and message chunks are not retained after an update.

Contexts are binaries of at most 255 bytes and default to `<<>>` where supported.
Pure Ed25519 has no context. Ed25519ctx uses domain separation even with an
empty context, so its signatures are distinct from pure Ed25519 signatures.

X25519 uses 32-byte secret scalars and public keys. The scalar is the first
argument to `x25519/2`; a rejected peer key returns `error`.

```erlang
{AlicePublic, AliceSecret} = libdecaf_curve25519:x25519_keypair(),
{BobPublic, BobSecret} = libdecaf_curve25519:x25519_keypair(),
Shared = libdecaf_curve25519:x25519(AliceSecret, BobPublic),
Shared = libdecaf_curve25519:x25519(BobSecret, AlicePublic).
```

Signature encodings follow [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html);
key agreement follows [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html).
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2016-02-29", modified => "2026-10-23"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

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
    eddsa_keypair_to_x25519_keypair/1,
    eddsa_pk_to_x25519_pk/1,
    eddsa_secret_to_x25519_keypair/1,
    eddsa_secret_to_x25519_secret/1,
    eddsa_sk_to_x25519_keypair/1
]).
% Ed25519
-export([
    ed25519_keypair_sign/2,
    ed25519_sign/2,
    ed25519_verify/3
]).
% Ed25519ctx
-export([
    ed25519ctx_keypair_sign/2,
    ed25519ctx_keypair_sign/3,
    ed25519ctx_sign/2,
    ed25519ctx_sign/3,
    ed25519ctx_verify/3,
    ed25519ctx_verify/4
]).
% Ed25519ph
-export([
    ed25519ph_keypair_sign/2,
    ed25519ph_keypair_sign/3,
    ed25519ph_keypair_sign_init/1,
    ed25519ph_keypair_sign_init/2,
    ed25519ph_sign/2,
    ed25519ph_sign/3,
    ed25519ph_sign_init/1,
    ed25519ph_sign_init/2,
    ed25519ph_sign_update/2,
    ed25519ph_sign_final/1,
    ed25519ph_verify/3,
    ed25519ph_verify/4,
    ed25519ph_verify_init/2,
    ed25519ph_verify_init/3,
    ed25519ph_verify_update/2,
    ed25519ph_verify_final/1
]).
% X25519
-export([
    curve25519/1,
    curve25519/2,
    x25519/1,
    x25519/2,
    x25519_keypair/0,
    x25519_keypair/1
]).

%%% Types

-doc """
A signature context of at most 255 bytes. The empty context is `<<>>`.
""".
-type context() :: binary().

-doc """
An integer or a 32-byte little-endian X25519 coordinate.
""".
-type coordinate() :: integer() | x25519_public_key().

-doc """
An immutable native Ed25519ph signing state retaining its keypair and context.
""".
-type ed25519ph_sign_state() :: libdecaf_nif:ed25519ph_sign_state().

-doc """
An immutable native Ed25519ph verification state retaining its signature, public key, and context.
""".
-type ed25519ph_verify_state() :: libdecaf_nif:ed25519ph_verify_state().

-doc """
A public key paired with the encoded signing key `<<Seed/binary, PublicKey/binary>>`.
""".
-type eddsa_keypair() :: {public_key(), secret_key()}.

-doc """
A native Ed25519 keypair resource, distinct from an encoded signing key.
""".
-type keypair() :: libdecaf_nif:ed25519_keypair().

-doc """
An original message for one-shot signing or verification. Streaming updates accept iodata instead.
""".
-type message() :: binary().

-doc """
A 32-byte Ed25519 public key.
""".
-type public_key() :: libdecaf_nif:ed25519_public_key().

-doc """
An integer or a 32-byte X25519 secret scalar.
""".
-type scalar() :: integer() | x25519_secret_key().

-doc """
A 64-byte signing key: the 32-byte secret seed followed by its matching public key.
""".
-type secret_key() :: libdecaf_nif:ed25519_signing_key().

-doc """
A 32-byte secret seed used to derive an Ed25519 keypair.
""".
-type seed() :: libdecaf_nif:ed25519_secret_key().

-doc """
A 64-byte Ed25519 signature encoding.
""".
-type signature() :: libdecaf_nif:ed25519_signature().

-doc """
An X25519 public key paired with its secret scalar.
""".
-type x25519_keypair() :: {x25519_public_key(), x25519_secret_key()}.

-doc """
A 32-byte X25519 public key.
""".
-type x25519_public_key() :: libdecaf_nif:x25519_public_key().

-doc """
A 32-byte X25519 secret scalar, distinct from an Ed25519 secret seed.
""".
-type x25519_secret_key() :: libdecaf_nif:x25519_scalar().

-doc """
A 32-byte X25519 shared secret.
""".
-type x25519_shared_secret() :: libdecaf_nif:x25519_shared_secret().

-export_type([
    context/0,
    coordinate/0,
    ed25519ph_sign_state/0,
    ed25519ph_verify_state/0,
    eddsa_keypair/0,
    keypair/0,
    message/0,
    public_key/0,
    scalar/0,
    secret_key/0,
    seed/0,
    signature/0,
    x25519_keypair/0,
    x25519_public_key/0,
    x25519_secret_key/0,
    x25519_shared_secret/0
]).

%% Macro
% EdDSA
-define(EdDSA_SECRET_BYTES, 32).
-define(EdDSA_PK_BYTES, 32).
-define(EdDSA_SK_BYTES, 64).
-define(EdDSA_SIGN_BYTES, 64).
% X25519
-define(X25519_PRIVATE_BYTES, 32).
-define(X25519_PUBLIC_BYTES, 32).

%%%===================================================================
%%% API functions
%%%===================================================================

% Keypair

-doc """
Generate a native Ed25519 keypair using `crypto:strong_rand_bytes/1`.
Use this resource with `ed25519_keypair_sign/2` or `ed25519ph_keypair_sign_init/1`.
""".
-spec keypair_random() -> Keypair when
    Keypair :: keypair().
keypair_random() ->
    keypair_derive(crypto:strong_rand_bytes(?EdDSA_SECRET_BYTES)).

-doc """
Derive a native Ed25519 keypair from a 32-byte secret seed.
The resource retains the seed and its derived public key.
""".
-spec keypair_derive(Seed) -> Keypair when
    Seed :: seed(), Keypair :: keypair().
keypair_derive(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?EdDSA_SECRET_BYTES
->
    libdecaf_nif:ed25519_derive_keypair(Secret).

-doc """
Extract the 32-byte secret seed from a native keypair.
This returns the seed alone, rather than the encoded seed/public key signing key.
""".
-spec keypair_extract_private_key(Keypair) -> Seed when
    Keypair :: keypair(), Seed :: seed().
keypair_extract_private_key(Keypair) ->
    libdecaf_nif:ed25519_keypair_extract_private_key(Keypair).

-doc """
Extract the 32-byte public key from a native Ed25519 keypair.
""".
-spec keypair_extract_public_key(Keypair) -> PublicKey when
    Keypair :: keypair(), PublicKey :: public_key().
keypair_extract_public_key(Keypair) ->
    libdecaf_nif:ed25519_keypair_extract_public_key(Keypair).

% EdDSA

-doc """
Generate a random encoded keypair `{PublicKey, <<Seed/binary, PublicKey/binary>>}`.
Use the second element with `ed25519_sign/2` or `ed25519ph_sign_init/1`.
""".
-spec eddsa_keypair() -> Keypair when
    Keypair :: eddsa_keypair().
eddsa_keypair() ->
    eddsa_keypair(crypto:strong_rand_bytes(?EdDSA_SECRET_BYTES)).

-doc """
Derive an encoded keypair from a 32-byte secret seed.
The returned signing key is the seed followed by its public key.
""".
-spec eddsa_keypair(Seed) -> Keypair when
    Seed :: seed(), Keypair :: eddsa_keypair().
eddsa_keypair(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?EdDSA_SECRET_BYTES
->
    PK = eddsa_secret_to_pk(Secret),
    {PK, <<Secret/binary, PK/binary>>}.

-doc """
Derive the Ed25519 public key from a secret seed.
""".
-spec eddsa_secret_to_pk(Seed) -> PublicKey when
    Seed :: seed(), PublicKey :: public_key().
eddsa_secret_to_pk(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?EdDSA_SECRET_BYTES
->
    libdecaf_nif:ed25519_derive_public_key(Secret).

-doc """
Extract the public-key bytes from an encoded signing key.
This only splits the encoding; it does not check that the seed and public key match.
""".
-spec eddsa_sk_to_pk(SigningKey) -> PublicKey when
    SigningKey :: secret_key(), PublicKey :: public_key().
eddsa_sk_to_pk(<<_:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>) ->
    PK.

-doc """
Extract the secret-seed bytes from an encoded signing key.
This only splits the encoding; it does not validate the public-key bytes.
""".
-spec eddsa_sk_to_secret(SigningKey) -> Seed when
    SigningKey :: secret_key(), Seed :: seed().
eddsa_sk_to_secret(<<Secret:?EdDSA_SECRET_BYTES/binary, _:?EdDSA_PK_BYTES/binary>>) ->
    Secret.

-doc """
Convert an encoded Ed25519 keypair to a X25519 keypair.
The supplied public key must match the public-key bytes in the signing key;
the converted public and private parts must also agree.
""".
-spec eddsa_keypair_to_x25519_keypair(Keypair) -> KeypairX when
    Keypair :: eddsa_keypair(), KeypairX :: x25519_keypair().
eddsa_keypair_to_x25519_keypair({
    <<PK:?EdDSA_PK_BYTES/binary>>, SK = <<_:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>
}) ->
    eddsa_sk_to_x25519_keypair(SK).

-doc """
Convert a Ed25519 public-key encoding to a X25519 public key.
This conversion alone does not establish ownership of the corresponding secret key.
""".
-spec eddsa_pk_to_x25519_pk(PublicKey) -> PublicKeyX when
    PublicKey :: public_key(), PublicKeyX :: x25519_public_key().
eddsa_pk_to_x25519_pk(<<PK:?EdDSA_PK_BYTES/binary>>) ->
    libdecaf_nif:ed25519_convert_public_key_to_x25519(PK).

-doc """
Derive an X25519 keypair from an Ed25519 secret seed.
This applies the upstream private-key conversion before deriving the X25519 public key.
""".
-spec eddsa_secret_to_x25519_keypair(Seed) -> KeypairX when
    Seed :: seed(), KeypairX :: x25519_keypair().
eddsa_secret_to_x25519_keypair(<<Secret:?EdDSA_SECRET_BYTES/binary>>) ->
    x25519_keypair(eddsa_secret_to_x25519_secret(Secret)).

-doc """
Convert a 32-byte Ed25519 secret seed to a 32-byte X25519 secret scalar.
""".
-spec eddsa_secret_to_x25519_secret(Seed) -> SecretX when
    Seed :: seed(), SecretX :: x25519_secret_key().
eddsa_secret_to_x25519_secret(<<Secret:?EdDSA_SECRET_BYTES/binary>>) ->
    libdecaf_nif:ed25519_convert_private_key_to_x25519(Secret).

-doc """
Convert an encoded Ed25519 signing key to a X25519 keypair.
Raise `{badarg, [SigningKey]}` if the converted public key differs from the
public key derived from the converted seed.
""".
-spec eddsa_sk_to_x25519_keypair(SigningKey) -> KeypairX when
    SigningKey :: secret_key(), KeypairX :: x25519_keypair().
eddsa_sk_to_x25519_keypair(SK = <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>) ->
    KP0 = {eddsa_pk_to_x25519_pk(PK), eddsa_secret_to_x25519_secret(Secret)},
    KP1 = eddsa_secret_to_x25519_keypair(Secret),
    case KP0 =:= KP1 of
        true ->
            KP1;
        false ->
            erlang:error({badarg, [SK]})
    end.

% Ed25519

-doc """
Sign a binary message using a native keypair and Ed25519.
The message is signed directly without the prehash variant.
This is pure Ed25519, without a context or Ed25519ctx domain separation.
""".
-spec ed25519_keypair_sign(Message, Keypair) -> Signature when
    Message :: message(), Keypair :: keypair(), Signature :: signature().
ed25519_keypair_sign(M, Keypair) when is_binary(M) ->
    libdecaf_nif:ed25519_keypair_sign(Keypair, M, 0, no_context).

-doc """
Sign a binary message using an encoded signing key and Ed25519.
The NIF verifies that its seed and public key match; a mismatch raises an error.
The message is signed directly without the prehash variant.
This is pure Ed25519, without a context or Ed25519ctx domain separation.
""".
-spec ed25519_sign(Message, SigningKey) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Signature :: signature().
ed25519_sign(M, <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>) when is_binary(M) ->
    libdecaf_nif:ed25519_sign(Secret, PK, M, 0, no_context).

-doc """
Verify a Ed25519 signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
The message is signed directly without the prehash variant.
This is pure Ed25519, without a context or Ed25519ctx domain separation.
""".
-spec ed25519_verify(Signature, Message, PublicKey) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Valid :: boolean().
ed25519_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>) when is_binary(M) ->
    libdecaf_nif:ed25519_verify(Sig, PK, M, 0, no_context).

% Ed25519ctx

-doc """
Sign a binary message using a native keypair and Ed25519ctx.
The message is signed directly without the prehash variant.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed25519ctx_keypair_sign(Message, Keypair) -> Signature when
    Message :: message(), Keypair :: keypair(), Signature :: signature().
ed25519ctx_keypair_sign(M, Keypair) when is_binary(M) ->
    ed25519ctx_keypair_sign(M, Keypair, <<>>).

-doc """
Sign a binary message using a native keypair and Ed25519ctx.
The message is signed directly without the prehash variant.
The context must be a binary of at most 255 bytes and must match between signing and verification.
Even `<<>>` selects Ed25519ctx domain separation, rather than pure Ed25519.
""".
-spec ed25519ctx_keypair_sign(Message, Keypair, Context) -> Signature when
    Message :: message(), Keypair :: keypair(), Context :: context(), Signature :: signature().
ed25519ctx_keypair_sign(M, Keypair, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed25519_keypair_sign(Keypair, M, 0, C).

-doc """
Sign a binary message using an encoded signing key and Ed25519ctx.
The NIF verifies that its seed and public key match; a mismatch raises an error.
The message is signed directly without the prehash variant.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed25519ctx_sign(Message, SigningKey) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Signature :: signature().
ed25519ctx_sign(M, <<SK:?EdDSA_SK_BYTES/binary>>) when is_binary(M) ->
    ed25519ctx_sign(M, SK, <<>>).

-doc """
Sign a binary message using an encoded signing key and Ed25519ctx.
The NIF verifies that its seed and public key match; a mismatch raises an error.
The message is signed directly without the prehash variant.
The context must be a binary of at most 255 bytes and must match between signing and verification.
Even `<<>>` selects Ed25519ctx domain separation, rather than pure Ed25519.
""".
-spec ed25519ctx_sign(Message, SigningKey, Context) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Context :: context(), Signature :: signature().
ed25519ctx_sign(M, <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed25519_sign(Secret, PK, M, 0, C).

-doc """
Verify a Ed25519ctx signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
The message is signed directly without the prehash variant.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed25519ctx_verify(Signature, Message, PublicKey) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Valid :: boolean().
ed25519ctx_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>) when is_binary(M) ->
    ed25519ctx_verify(Sig, M, PK, <<>>).

-doc """
Verify a Ed25519ctx signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
The message is signed directly without the prehash variant.
The context must be a binary of at most 255 bytes and must match between signing and verification.
Even `<<>>` selects Ed25519ctx domain separation, rather than pure Ed25519.
""".
-spec ed25519ctx_verify(Signature, Message, PublicKey, Context) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Context :: context(), Valid :: boolean().
ed25519ctx_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed25519_verify(Sig, PK, M, 0, C).

% Ed25519ph

-doc """
Sign a binary message using a native keypair and Ed25519ph.
Pass the original message; Ed25519ph computes its SHA-512 prehash internally.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed25519ph_keypair_sign(Message, Keypair) -> Signature when
    Message :: message(), Keypair :: keypair(), Signature :: signature().
ed25519ph_keypair_sign(M, Keypair) when is_binary(M) ->
    ed25519ph_keypair_sign(M, Keypair, <<>>).

-doc """
Sign a binary message using a native keypair and Ed25519ph.
Pass the original message; Ed25519ph computes its SHA-512 prehash internally.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed25519ph_keypair_sign(Message, Keypair, Context) -> Signature when
    Message :: message(), Keypair :: keypair(), Context :: context(), Signature :: signature().
ed25519ph_keypair_sign(M, Keypair, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed25519_keypair_sign_prehash(Keypair, M, C).

-doc """
Start native Ed25519ph signing using a keypair resource.
The state retains the keypair, so the caller does not need to keep another reference.
Continue with `ed25519ph_sign_update/2` and `ed25519ph_sign_final/1`.
The context defaults to `<<>>`.
""".
-spec ed25519ph_keypair_sign_init(Keypair) -> State when
    Keypair :: keypair(), State :: ed25519ph_sign_state().
ed25519ph_keypair_sign_init(Keypair) ->
    libdecaf_nif:ed25519ph_keypair_sign_init(Keypair).

-doc """
Start native Ed25519ph signing using a keypair resource.
The state retains the keypair, so the caller does not need to keep another reference.
Continue with `ed25519ph_sign_update/2` and `ed25519ph_sign_final/1`.
The context must contain at most 255 bytes. For example:

```erlang
Keypair = libdecaf_curve25519:keypair_random(),
S0 = libdecaf_curve25519:ed25519ph_keypair_sign_init(Keypair, <<"example">>),
S1 = libdecaf_curve25519:ed25519ph_sign_update(S0, [<<"hello ">>, <<"world">>]),
Signature = libdecaf_curve25519:ed25519ph_sign_final(S1).
```
""".
-spec ed25519ph_keypair_sign_init(Keypair, Context) -> State when
    Keypair :: keypair(), Context :: context(), State :: ed25519ph_sign_state().
ed25519ph_keypair_sign_init(Keypair, Context) ->
    libdecaf_nif:ed25519ph_keypair_sign_init(Keypair, Context).

-doc """
Sign a binary message using an encoded signing key and Ed25519ph.
The NIF verifies that its seed and public key match; a mismatch raises an error.
Pass the original message; Ed25519ph computes its SHA-512 prehash internally.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed25519ph_sign(Message, SigningKey) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Signature :: signature().
ed25519ph_sign(M, <<SK:?EdDSA_SK_BYTES/binary>>) when is_binary(M) ->
    ed25519ph_sign(M, SK, <<>>).

-doc """
Sign a binary message using an encoded signing key and Ed25519ph.
The NIF verifies that its seed and public key match; a mismatch raises an error.
Pass the original message; Ed25519ph computes its SHA-512 prehash internally.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed25519ph_sign(Message, SigningKey, Context) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Context :: context(), Signature :: signature().
ed25519ph_sign(M, <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed25519_sign_prehash(Secret, PK, M, C).

-doc """
Start native Ed25519ph signing using `<<Seed/binary, PublicKey/binary>>`.
The NIF validates that both parts match and creates a retained native keypair;
a mismatch raises an error.
Continue with `ed25519ph_sign_update/2` and `ed25519ph_sign_final/1`.
The context defaults to `<<>>`.
""".
-spec ed25519ph_sign_init(SigningKey) -> State when
    SigningKey :: secret_key(), State :: ed25519ph_sign_state().
ed25519ph_sign_init(SigningKey) ->
    libdecaf_nif:ed25519ph_sign_init(SigningKey).

-doc """
Start native Ed25519ph signing using `<<Seed/binary, PublicKey/binary>>`.
The NIF validates that both parts match and creates a retained native keypair;
a mismatch raises an error.
Continue with `ed25519ph_sign_update/2` and `ed25519ph_sign_final/1`.
The context must contain at most 255 bytes. For example:

```erlang
{_PublicKey, SigningKey} = libdecaf_curve25519:eddsa_keypair(),
S0 = libdecaf_curve25519:ed25519ph_sign_init(SigningKey, <<"example">>),
S1 = libdecaf_curve25519:ed25519ph_sign_update(S0, [<<"hello ">>, <<"world">>]),
Signature = libdecaf_curve25519:ed25519ph_sign_final(S1).
```
""".
-spec ed25519ph_sign_init(SigningKey, Context) -> State when
    SigningKey :: secret_key(), Context :: context(), State :: ed25519ph_sign_state().
ed25519ph_sign_init(SigningKey, Context) ->
    libdecaf_nif:ed25519ph_sign_init(SigningKey, Context).

-doc """
Prehash another chunk of the original message and return the next signing state.
Both signing initializers use this function. The input state is unchanged, so it
can be reused or branched. Large inputs yield; the chunk is released after the update.
""".
-spec ed25519ph_sign_update(State, Input) -> NextState when
    State :: ed25519ph_sign_state(), Input :: iodata(), NextState :: ed25519ph_sign_state().
ed25519ph_sign_update(State, Input) ->
    libdecaf_nif:ed25519ph_sign_update(State, Input).

-doc """
Sign the accumulated message with the retained keypair and context.
The result matches `ed25519ph_keypair_sign/3` for the same message, keypair,
and context. Finalization leaves the state reusable and produces the same
signature when repeated; it does not sign a caller-supplied digest.
""".
-spec ed25519ph_sign_final(State) -> Signature when
    State :: ed25519ph_sign_state(), Signature :: signature().
ed25519ph_sign_final(State) ->
    libdecaf_nif:ed25519ph_sign_final(State).

-doc """
Verify a Ed25519ph signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
Pass the original message; Ed25519ph computes its SHA-512 prehash internally.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed25519ph_verify(Signature, Message, PublicKey) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Valid :: boolean().
ed25519ph_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>) when is_binary(M) ->
    ed25519ph_verify(Sig, M, PK, <<>>).

-doc """
Verify a Ed25519ph signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
Pass the original message; Ed25519ph computes its SHA-512 prehash internally.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed25519ph_verify(Signature, Message, PublicKey, Context) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Context :: context(), Valid :: boolean().
ed25519ph_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed25519_verify_prehash(Sig, PK, M, C).

-doc """
Start native Ed25519ph verification, retaining the signature and public key.
The signature and public key must have 64 and 32 bytes respectively.
Cryptographic verification happens in `ed25519ph_verify_final/1`.
The context defaults to `<<>>`.
""".
-spec ed25519ph_verify_init(Signature, PublicKey) -> State when
    Signature :: signature(), PublicKey :: public_key(), State :: ed25519ph_verify_state().
ed25519ph_verify_init(Signature, PublicKey) ->
    libdecaf_nif:ed25519ph_verify_init(Signature, PublicKey).

-doc """
Start native Ed25519ph verification, retaining the signature and public key.
The signature and public key must have 64 and 32 bytes respectively.
Cryptographic verification happens in `ed25519ph_verify_final/1`.
The context must match the signing context and contain at most 255 bytes.

```erlang
Keypair = libdecaf_curve25519:keypair_random(),
PublicKey = libdecaf_curve25519:keypair_extract_public_key(Keypair),
Signature = libdecaf_curve25519:ed25519ph_keypair_sign(<<"hello world">>, Keypair, <<"example">>),
V0 = libdecaf_curve25519:ed25519ph_verify_init(Signature, PublicKey, <<"example">>),
V1 = libdecaf_curve25519:ed25519ph_verify_update(V0, [<<"hello ">>, <<"world">>]),
true = libdecaf_curve25519:ed25519ph_verify_final(V1).
```
""".
-spec ed25519ph_verify_init(Signature, PublicKey, Context) -> State when
    Signature :: signature(), PublicKey :: public_key(), Context :: context(), State :: ed25519ph_verify_state().
ed25519ph_verify_init(Signature, PublicKey, Context) ->
    libdecaf_nif:ed25519ph_verify_init(Signature, PublicKey, Context).

-doc """
Prehash another chunk of the original message and return the next verification state.
The input state is unchanged. Large updates yield; a signing state or state
from another algorithm is rejected.
""".
-spec ed25519ph_verify_update(State, Input) -> NextState when
    State :: ed25519ph_verify_state(), Input :: iodata(), NextState :: ed25519ph_verify_state().
ed25519ph_verify_update(State, Input) ->
    libdecaf_nif:ed25519ph_verify_update(State, Input).

-doc """
Verify the accumulated message against the retained signature, public key, and context.
Return `false` if verification fails. The state remains reusable, so repeated
finalization returns the same result.
""".
-spec ed25519ph_verify_final(State) -> Valid when
    State :: ed25519ph_verify_state(), Valid :: boolean().
ed25519ph_verify_final(State) ->
    libdecaf_nif:ed25519ph_verify_final(State).

% X25519

-doc """
Derive an X25519 public coordinate and return it as a little-endian integer.
Integer scalars are encoded using their low 256 bits before the X25519 operation.
Use `x25519/1` for the binary-returning interface.
""".
-spec curve25519(Scalar) -> Coordinate when
    Scalar :: scalar(), Coordinate :: non_neg_integer().
curve25519(Scalar) when is_integer(Scalar) ->
    curve25519(<<Scalar:?X25519_PRIVATE_BYTES/unsigned-little-integer-unit:8>>);
curve25519(Scalar) when
    is_binary(Scalar) andalso
        byte_size(Scalar) =:= ?X25519_PRIVATE_BYTES
->
    <<U:?X25519_PUBLIC_BYTES/unsigned-little-integer-unit:8>> = libdecaf_nif:x25519_derive_public_key(Scalar),
    U.

-doc """
Compute X25519 with an integer or binary scalar and peer coordinate.
Integers are encoded using their low 256 bits; the result is decoded as a
little-endian integer. A rejected peer key raises `{badmatch, error}`.
Use `x25519/2` for a binary result or the atom `error`.
""".
-spec curve25519(Scalar, Coordinate) -> SharedCoordinate when
    Scalar :: scalar(), Coordinate :: coordinate(), SharedCoordinate :: non_neg_integer().
curve25519(Scalar, Base) when is_integer(Scalar) ->
    curve25519(<<Scalar:?X25519_PRIVATE_BYTES/unsigned-little-integer-unit:8>>, Base);
curve25519(Scalar, Base) when is_integer(Base) ->
    curve25519(Scalar, <<Base:?X25519_PUBLIC_BYTES/unsigned-little-integer-unit:8>>);
curve25519(Scalar, Base) when
    is_binary(Scalar) andalso
        byte_size(Scalar) =:= ?X25519_PRIVATE_BYTES andalso
        is_binary(Base) andalso
        byte_size(Base) =:= ?X25519_PUBLIC_BYTES
->
    <<U:?X25519_PUBLIC_BYTES/unsigned-little-integer-unit:8>> = libdecaf_nif:x25519(Base, Scalar),
    U.

-doc """
Derive a 32-byte X25519 public key from a secret scalar.
The scalar is clamped by the native X25519 operation.
""".
-spec x25519(Secret) -> PublicKey when
    Secret :: x25519_secret_key(), PublicKey :: x25519_public_key().
x25519(K) when
    is_binary(K) andalso
        byte_size(K) =:= ?X25519_PRIVATE_BYTES
->
    libdecaf_nif:x25519_derive_public_key(K).

-doc """
Compute an X25519 shared secret with the secret scalar first and peer public key second.
Return `error` when the native operation rejects a peer key, including low-order
inputs producing an all-zero shared secret. Both keys must have 32 bytes.
""".
-spec x25519(Secret, PeerPublicKey) -> SharedSecret when
    Secret :: x25519_secret_key(), PeerPublicKey :: x25519_public_key(), SharedSecret :: x25519_shared_secret() | error.
x25519(K, U) when
    is_binary(K) andalso
        byte_size(K) =:= ?X25519_PRIVATE_BYTES andalso
        is_binary(U) andalso
        byte_size(U) =:= ?X25519_PUBLIC_BYTES
->
    libdecaf_nif:x25519(U, K).

-doc """
Generate a random X25519 keypair `{PublicKey, SecretScalar}`.
The secret scalar contains 32 random bytes from `crypto:strong_rand_bytes/1`.
""".
-spec x25519_keypair() -> Keypair when
    Keypair :: x25519_keypair().
x25519_keypair() ->
    x25519_keypair(crypto:strong_rand_bytes(?X25519_PRIVATE_BYTES)).

-doc """
Derive an X25519 keypair `{PublicKey, SecretScalar}` from the supplied scalar.
The returned scalar bytes are the supplied bytes; clamping happens inside X25519.
""".
-spec x25519_keypair(Secret) -> Keypair when
    Secret :: x25519_secret_key(), Keypair :: x25519_keypair().
x25519_keypair(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?X25519_PRIVATE_BYTES
->
    {x25519(Secret), Secret}.
