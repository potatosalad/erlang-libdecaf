%%% % @format
-module(libdecaf_curve448).
-moduledoc """
Ed448 signatures, native streaming Ed448ph, and X448 key agreement.

`keypair_random/0` and `keypair_derive/1` return native keypair resources.
`keypair_extract_private_key/1` returns the 57-byte secret seed. In contrast,
`eddsa_keypair/0,1` returns `{PublicKey, SigningKey}`, where the 114-byte
signing key is `<<Seed/binary, PublicKey/binary>>`.

Sign and verify a binary message using a native keypair:

```erlang
Keypair = libdecaf_curve448:keypair_random(),
PublicKey = libdecaf_curve448:keypair_extract_public_key(Keypair),
Signature = libdecaf_curve448:ed448_keypair_sign(<<"message">>, Keypair),
true = libdecaf_curve448:ed448_verify(Signature, <<"message">>, PublicKey).
```

`ed448ph` prehashes the original message using SHAKE256 with a 64-byte output. Do not prehash the message yourself.
Streaming prehash signing keeps the keypair, context, and prehash in native
resources and accepts iodata chunks:

```erlang
{PublicKey, SigningKey} = libdecaf_curve448:eddsa_keypair(),
S0 = libdecaf_curve448:ed448ph_sign_init(SigningKey, <<"example">>),
S1 = libdecaf_curve448:ed448ph_sign_update(S0, [<<"first ">>, <<"chunk">>]),
S2 = libdecaf_curve448:ed448ph_sign_update(S1, <<"second chunk">>),
Signature = libdecaf_curve448:ed448ph_sign_final(S2),
V0 = libdecaf_curve448:ed448ph_verify_init(Signature, PublicKey, <<"example">>),
V1 = libdecaf_curve448:ed448ph_verify_update(V0, <<"first chunksecond chunk">>),
true = libdecaf_curve448:ed448ph_verify_final(V1).
```

Use `ed448ph_keypair_sign_init/1,2` when you already have a native keypair.
Both initializers produce the same signing state. Each update returns a new
immutable state; finalization leaves its input reusable. Signing and verification
states are distinct, and states from the other curve are rejected. Large updates
yield to the scheduler, and message chunks are not retained after an update.

Contexts are binaries of at most 255 bytes and default to `<<>>` where supported.

X448 uses 56-byte secret scalars and public keys. The scalar is the first
argument to `x448/2`; a rejected peer key returns `error`.

```erlang
{AlicePublic, AliceSecret} = libdecaf_curve448:x448_keypair(),
{BobPublic, BobSecret} = libdecaf_curve448:x448_keypair(),
Shared = libdecaf_curve448:x448(AliceSecret, BobPublic),
Shared = libdecaf_curve448:x448(BobSecret, AlicePublic).
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
    ed448ph_keypair_sign_init/1,
    ed448ph_keypair_sign_init/2,
    ed448ph_sign/2,
    ed448ph_sign/3,
    ed448ph_sign_init/1,
    ed448ph_sign_init/2,
    ed448ph_sign_update/2,
    ed448ph_sign_final/1,
    ed448ph_verify/3,
    ed448ph_verify/4,
    ed448ph_verify_init/2,
    ed448ph_verify_init/3,
    ed448ph_verify_update/2,
    ed448ph_verify_final/1
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

%%% Types

-doc """
A signature context of at most 255 bytes. The empty context is `<<>>`.
""".
-type context() :: binary().

-doc """
An integer or a 56-byte little-endian X448 coordinate.
""".
-type coordinate() :: integer() | x448_public_key().

-doc """
An immutable native Ed448ph signing state retaining its keypair and context.
""".
-type ed448ph_sign_state() :: libdecaf_nif:ed448ph_sign_state().

-doc """
An immutable native Ed448ph verification state retaining its signature, public key, and context.
""".
-type ed448ph_verify_state() :: libdecaf_nif:ed448ph_verify_state().

-doc """
A public key paired with the encoded signing key `<<Seed/binary, PublicKey/binary>>`.
""".
-type eddsa_keypair() :: {public_key(), secret_key()}.

-doc """
A native Ed448 keypair resource, distinct from an encoded signing key.
""".
-type keypair() :: libdecaf_nif:ed448_keypair().

-doc """
An original message for one-shot signing or verification. Streaming updates accept iodata instead.
""".
-type message() :: binary().

-doc """
A 57-byte Ed448 public key.
""".
-type public_key() :: libdecaf_nif:ed448_public_key().

-doc """
An integer or a 56-byte X448 secret scalar.
""".
-type scalar() :: integer() | x448_secret_key().

-doc """
A 114-byte signing key: the 57-byte secret seed followed by its matching public key.
""".
-type secret_key() :: libdecaf_nif:ed448_signing_key().

-doc """
A 57-byte secret seed used to derive an Ed448 keypair.
""".
-type seed() :: libdecaf_nif:ed448_secret_key().

-doc """
A 114-byte Ed448 signature encoding.
""".
-type signature() :: libdecaf_nif:ed448_signature().

-doc """
An X448 public key paired with its secret scalar.
""".
-type x448_keypair() :: {x448_public_key(), x448_secret_key()}.

-doc """
A 56-byte X448 public key.
""".
-type x448_public_key() :: libdecaf_nif:x448_public_key().

-doc """
A 56-byte X448 secret scalar, distinct from an Ed448 secret seed.
""".
-type x448_secret_key() :: libdecaf_nif:x448_scalar().

-doc """
A 56-byte X448 shared secret.
""".
-type x448_shared_secret() :: libdecaf_nif:x448_shared_secret().

-export_type([
    context/0,
    coordinate/0,
    ed448ph_sign_state/0,
    ed448ph_verify_state/0,
    eddsa_keypair/0,
    keypair/0,
    message/0,
    public_key/0,
    scalar/0,
    secret_key/0,
    seed/0,
    signature/0,
    x448_keypair/0,
    x448_public_key/0,
    x448_secret_key/0,
    x448_shared_secret/0
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

-doc """
Generate a native Ed448 keypair using `crypto:strong_rand_bytes/1`.
Use this resource with `ed448_keypair_sign/2` or `ed448ph_keypair_sign_init/1`.
""".
-spec keypair_random() -> Keypair when
    Keypair :: keypair().
keypair_random() ->
    keypair_derive(crypto:strong_rand_bytes(?EdDSA_SECRET_BYTES)).

-doc """
Derive a native Ed448 keypair from a 57-byte secret seed.
The resource retains the seed and its derived public key.
""".
-spec keypair_derive(Seed) -> Keypair when
    Seed :: seed(), Keypair :: keypair().
keypair_derive(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?EdDSA_SECRET_BYTES
->
    libdecaf_nif:ed448_derive_keypair(Secret).

-doc """
Extract the 57-byte secret seed from a native keypair.
This returns the seed alone, rather than the encoded seed/public key signing key.
""".
-spec keypair_extract_private_key(Keypair) -> Seed when
    Keypair :: keypair(), Seed :: seed().
keypair_extract_private_key(Keypair) ->
    libdecaf_nif:ed448_keypair_extract_private_key(Keypair).

-doc """
Extract the 57-byte public key from a native Ed448 keypair.
""".
-spec keypair_extract_public_key(Keypair) -> PublicKey when
    Keypair :: keypair(), PublicKey :: public_key().
keypair_extract_public_key(Keypair) ->
    libdecaf_nif:ed448_keypair_extract_public_key(Keypair).

% EdDSA

-doc """
Generate a random encoded keypair `{PublicKey, <<Seed/binary, PublicKey/binary>>}`.
Use the second element with `ed448_sign/2` or `ed448ph_sign_init/1`.
""".
-spec eddsa_keypair() -> Keypair when
    Keypair :: eddsa_keypair().
eddsa_keypair() ->
    eddsa_keypair(crypto:strong_rand_bytes(?EdDSA_SECRET_BYTES)).

-doc """
Derive an encoded keypair from a 57-byte secret seed.
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
Derive the Ed448 public key from a secret seed.
""".
-spec eddsa_secret_to_pk(Seed) -> PublicKey when
    Seed :: seed(), PublicKey :: public_key().
eddsa_secret_to_pk(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?EdDSA_SECRET_BYTES
->
    libdecaf_nif:ed448_derive_public_key(Secret).

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
Convert an encoded Ed448 keypair to a X448 keypair.
The supplied public key must match the public-key bytes in the signing key;
the converted public and private parts must also agree.
""".
-spec eddsa_keypair_to_x448_keypair(Keypair) -> KeypairX when
    Keypair :: eddsa_keypair(), KeypairX :: x448_keypair().
eddsa_keypair_to_x448_keypair({
    <<PK:?EdDSA_PK_BYTES/binary>>, SK = <<_:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>
}) ->
    eddsa_sk_to_x448_keypair(SK).

-doc """
Convert a Ed448 public-key encoding to a X448 public key.
This conversion alone does not establish ownership of the corresponding secret key.
""".
-spec eddsa_pk_to_x448_pk(PublicKey) -> PublicKeyX when
    PublicKey :: public_key(), PublicKeyX :: x448_public_key().
eddsa_pk_to_x448_pk(<<PK:?EdDSA_PK_BYTES/binary>>) ->
    libdecaf_nif:ed448_convert_public_key_to_x448(PK).

-doc """
Derive an X448 keypair from an Ed448 secret seed.
This applies the upstream private-key conversion before deriving the X448 public key.
""".
-spec eddsa_secret_to_x448_keypair(Seed) -> KeypairX when
    Seed :: seed(), KeypairX :: x448_keypair().
eddsa_secret_to_x448_keypair(<<Secret:?EdDSA_SECRET_BYTES/binary>>) ->
    x448_keypair(eddsa_secret_to_x448_secret(Secret)).

-doc """
Convert a 57-byte Ed448 secret seed to a 56-byte X448 secret scalar.
""".
-spec eddsa_secret_to_x448_secret(Seed) -> SecretX when
    Seed :: seed(), SecretX :: x448_secret_key().
eddsa_secret_to_x448_secret(<<Secret:?EdDSA_SECRET_BYTES/binary>>) ->
    libdecaf_nif:ed448_convert_private_key_to_x448(Secret).

-doc """
Convert an encoded Ed448 signing key to a X448 keypair.
Raise `{badarg, [SigningKey]}` if the converted public key differs from the
public key derived from the converted seed.
""".
-spec eddsa_sk_to_x448_keypair(SigningKey) -> KeypairX when
    SigningKey :: secret_key(), KeypairX :: x448_keypair().
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

-doc """
Sign a binary message using a native keypair and Ed448.
The message is signed directly without the prehash variant.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed448_keypair_sign(Message, Keypair) -> Signature when
    Message :: message(), Keypair :: keypair(), Signature :: signature().
ed448_keypair_sign(M, Keypair) when is_binary(M) ->
    ed448_keypair_sign(M, Keypair, <<>>).

-doc """
Sign a binary message using a native keypair and Ed448.
The message is signed directly without the prehash variant.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed448_keypair_sign(Message, Keypair, Context) -> Signature when
    Message :: message(), Keypair :: keypair(), Context :: context(), Signature :: signature().
ed448_keypair_sign(M, Keypair, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_keypair_sign(Keypair, M, 0, C).

-doc """
Sign a binary message using an encoded signing key and Ed448.
The NIF verifies that its seed and public key match; a mismatch raises an error.
The message is signed directly without the prehash variant.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed448_sign(Message, SigningKey) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Signature :: signature().
ed448_sign(M, <<SK:?EdDSA_SK_BYTES/binary>>) when is_binary(M) ->
    ed448_sign(M, SK, <<>>).

-doc """
Sign a binary message using an encoded signing key and Ed448.
The NIF verifies that its seed and public key match; a mismatch raises an error.
The message is signed directly without the prehash variant.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed448_sign(Message, SigningKey, Context) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Context :: context(), Signature :: signature().
ed448_sign(M, <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_sign(Secret, PK, M, 0, C).

-doc """
Verify a Ed448 signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
The message is signed directly without the prehash variant.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed448_verify(Signature, Message, PublicKey) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Valid :: boolean().
ed448_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>) when is_binary(M) ->
    ed448_verify(Sig, M, PK, <<>>).

-doc """
Verify a Ed448 signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
The message is signed directly without the prehash variant.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed448_verify(Signature, Message, PublicKey, Context) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Context :: context(), Valid :: boolean().
ed448_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_verify(Sig, PK, M, 0, C).

% Ed448ph

-doc """
Sign a binary message using a native keypair and Ed448ph.
Pass the original message; Ed448ph computes its 64-byte SHAKE256 prehash internally.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed448ph_keypair_sign(Message, Keypair) -> Signature when
    Message :: message(), Keypair :: keypair(), Signature :: signature().
ed448ph_keypair_sign(M, Keypair) when is_binary(M) ->
    ed448ph_keypair_sign(M, Keypair, <<>>).

-doc """
Sign a binary message using a native keypair and Ed448ph.
Pass the original message; Ed448ph computes its 64-byte SHAKE256 prehash internally.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed448ph_keypair_sign(Message, Keypair, Context) -> Signature when
    Message :: message(), Keypair :: keypair(), Context :: context(), Signature :: signature().
ed448ph_keypair_sign(M, Keypair, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_keypair_sign_prehash(Keypair, M, C).

-doc """
Start native Ed448ph signing using a keypair resource.
The state retains the keypair, so the caller does not need to keep another reference.
Continue with `ed448ph_sign_update/2` and `ed448ph_sign_final/1`.
The context defaults to `<<>>`.
""".
-spec ed448ph_keypair_sign_init(Keypair) -> State when
    Keypair :: keypair(), State :: ed448ph_sign_state().
ed448ph_keypair_sign_init(Keypair) ->
    libdecaf_nif:ed448ph_keypair_sign_init(Keypair).

-doc """
Start native Ed448ph signing using a keypair resource.
The state retains the keypair, so the caller does not need to keep another reference.
Continue with `ed448ph_sign_update/2` and `ed448ph_sign_final/1`.
The context must contain at most 255 bytes. For example:

```erlang
Keypair = libdecaf_curve448:keypair_random(),
S0 = libdecaf_curve448:ed448ph_keypair_sign_init(Keypair, <<"example">>),
S1 = libdecaf_curve448:ed448ph_sign_update(S0, [<<"hello ">>, <<"world">>]),
Signature = libdecaf_curve448:ed448ph_sign_final(S1).
```
""".
-spec ed448ph_keypair_sign_init(Keypair, Context) -> State when
    Keypair :: keypair(), Context :: context(), State :: ed448ph_sign_state().
ed448ph_keypair_sign_init(Keypair, Context) ->
    libdecaf_nif:ed448ph_keypair_sign_init(Keypair, Context).

-doc """
Sign a binary message using an encoded signing key and Ed448ph.
The NIF verifies that its seed and public key match; a mismatch raises an error.
Pass the original message; Ed448ph computes its 64-byte SHAKE256 prehash internally.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed448ph_sign(Message, SigningKey) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Signature :: signature().
ed448ph_sign(M, <<SK:?EdDSA_SK_BYTES/binary>>) when is_binary(M) ->
    ed448ph_sign(M, SK, <<>>).

-doc """
Sign a binary message using an encoded signing key and Ed448ph.
The NIF verifies that its seed and public key match; a mismatch raises an error.
Pass the original message; Ed448ph computes its 64-byte SHAKE256 prehash internally.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed448ph_sign(Message, SigningKey, Context) -> Signature when
    Message :: message(), SigningKey :: secret_key(), Context :: context(), Signature :: signature().
ed448ph_sign(M, <<Secret:?EdDSA_SECRET_BYTES/binary, PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_sign_prehash(Secret, PK, M, C).

-doc """
Start native Ed448ph signing using `<<Seed/binary, PublicKey/binary>>`.
The NIF validates that both parts match and creates a retained native keypair;
a mismatch raises an error.
Continue with `ed448ph_sign_update/2` and `ed448ph_sign_final/1`.
The context defaults to `<<>>`.
""".
-spec ed448ph_sign_init(SigningKey) -> State when
    SigningKey :: secret_key(), State :: ed448ph_sign_state().
ed448ph_sign_init(SigningKey) ->
    libdecaf_nif:ed448ph_sign_init(SigningKey).

-doc """
Start native Ed448ph signing using `<<Seed/binary, PublicKey/binary>>`.
The NIF validates that both parts match and creates a retained native keypair;
a mismatch raises an error.
Continue with `ed448ph_sign_update/2` and `ed448ph_sign_final/1`.
The context must contain at most 255 bytes. For example:

```erlang
{_PublicKey, SigningKey} = libdecaf_curve448:eddsa_keypair(),
S0 = libdecaf_curve448:ed448ph_sign_init(SigningKey, <<"example">>),
S1 = libdecaf_curve448:ed448ph_sign_update(S0, [<<"hello ">>, <<"world">>]),
Signature = libdecaf_curve448:ed448ph_sign_final(S1).
```
""".
-spec ed448ph_sign_init(SigningKey, Context) -> State when
    SigningKey :: secret_key(), Context :: context(), State :: ed448ph_sign_state().
ed448ph_sign_init(SigningKey, Context) ->
    libdecaf_nif:ed448ph_sign_init(SigningKey, Context).

-doc """
Prehash another chunk of the original message and return the next signing state.
Both signing initializers use this function. The input state is unchanged, so it
can be reused or branched. Large inputs yield; the chunk is released after the update.
""".
-spec ed448ph_sign_update(State, Input) -> NextState when
    State :: ed448ph_sign_state(), Input :: iodata(), NextState :: ed448ph_sign_state().
ed448ph_sign_update(State, Input) ->
    libdecaf_nif:ed448ph_sign_update(State, Input).

-doc """
Sign the accumulated message with the retained keypair and context.
The result matches `ed448ph_keypair_sign/3` for the same message, keypair,
and context. Finalization leaves the state reusable and produces the same
signature when repeated; it does not sign a caller-supplied digest.
""".
-spec ed448ph_sign_final(State) -> Signature when
    State :: ed448ph_sign_state(), Signature :: signature().
ed448ph_sign_final(State) ->
    libdecaf_nif:ed448ph_sign_final(State).

-doc """
Verify a Ed448ph signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
Pass the original message; Ed448ph computes its 64-byte SHAKE256 prehash internally.
Use an empty context, equivalent to passing `<<>>` to the next arity.
""".
-spec ed448ph_verify(Signature, Message, PublicKey) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Valid :: boolean().
ed448ph_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>) when is_binary(M) ->
    ed448ph_verify(Sig, M, PK, <<>>).

-doc """
Verify a Ed448ph signature over a binary message.
Return `false` for a correctly sized signature that does not verify.
Pass the original message; Ed448ph computes its 64-byte SHAKE256 prehash internally.
The context must be a binary of at most 255 bytes and must match between signing and verification.
""".
-spec ed448ph_verify(Signature, Message, PublicKey, Context) -> Valid when
    Signature :: signature(), Message :: message(), PublicKey :: public_key(), Context :: context(), Valid :: boolean().
ed448ph_verify(<<Sig:?EdDSA_SIGN_BYTES/binary>>, M, <<PK:?EdDSA_PK_BYTES/binary>>, C) when
    is_binary(M) andalso
        is_binary(C) andalso
        byte_size(C) =< 255
->
    libdecaf_nif:ed448_verify_prehash(Sig, PK, M, C).

-doc """
Start native Ed448ph verification, retaining the signature and public key.
The signature and public key must have 114 and 57 bytes respectively.
Cryptographic verification happens in `ed448ph_verify_final/1`.
The context defaults to `<<>>`.
""".
-spec ed448ph_verify_init(Signature, PublicKey) -> State when
    Signature :: signature(), PublicKey :: public_key(), State :: ed448ph_verify_state().
ed448ph_verify_init(Signature, PublicKey) ->
    libdecaf_nif:ed448ph_verify_init(Signature, PublicKey).

-doc """
Start native Ed448ph verification, retaining the signature and public key.
The signature and public key must have 114 and 57 bytes respectively.
Cryptographic verification happens in `ed448ph_verify_final/1`.
The context must match the signing context and contain at most 255 bytes.

```erlang
Keypair = libdecaf_curve448:keypair_random(),
PublicKey = libdecaf_curve448:keypair_extract_public_key(Keypair),
Signature = libdecaf_curve448:ed448ph_keypair_sign(<<"hello world">>, Keypair, <<"example">>),
V0 = libdecaf_curve448:ed448ph_verify_init(Signature, PublicKey, <<"example">>),
V1 = libdecaf_curve448:ed448ph_verify_update(V0, [<<"hello ">>, <<"world">>]),
true = libdecaf_curve448:ed448ph_verify_final(V1).
```
""".
-spec ed448ph_verify_init(Signature, PublicKey, Context) -> State when
    Signature :: signature(), PublicKey :: public_key(), Context :: context(), State :: ed448ph_verify_state().
ed448ph_verify_init(Signature, PublicKey, Context) ->
    libdecaf_nif:ed448ph_verify_init(Signature, PublicKey, Context).

-doc """
Prehash another chunk of the original message and return the next verification state.
The input state is unchanged. Large updates yield; a signing state or state
from another algorithm is rejected.
""".
-spec ed448ph_verify_update(State, Input) -> NextState when
    State :: ed448ph_verify_state(), Input :: iodata(), NextState :: ed448ph_verify_state().
ed448ph_verify_update(State, Input) ->
    libdecaf_nif:ed448ph_verify_update(State, Input).

-doc """
Verify the accumulated message against the retained signature, public key, and context.
Return `false` if verification fails. The state remains reusable, so repeated
finalization returns the same result.
""".
-spec ed448ph_verify_final(State) -> Valid when
    State :: ed448ph_verify_state(), Valid :: boolean().
ed448ph_verify_final(State) ->
    libdecaf_nif:ed448ph_verify_final(State).

% X448

-doc """
Derive an X448 public coordinate and return it as a little-endian integer.
Integer scalars are encoded using their low 448 bits before the X448 operation.
Use `x448/1` for the binary-returning interface.
""".
-spec curve448(Scalar) -> Coordinate when
    Scalar :: scalar(), Coordinate :: non_neg_integer().
curve448(Scalar) when is_integer(Scalar) ->
    curve448(<<Scalar:?X448_PRIVATE_BYTES/unsigned-little-integer-unit:8>>);
curve448(Scalar) when
    is_binary(Scalar) andalso
        byte_size(Scalar) =:= ?X448_PRIVATE_BYTES
->
    <<U:?X448_PUBLIC_BYTES/unsigned-little-integer-unit:8>> = libdecaf_nif:x448_derive_public_key(Scalar),
    U.

-doc """
Compute X448 with an integer or binary scalar and peer coordinate.
Integers are encoded using their low 448 bits; the result is decoded as a
little-endian integer. A rejected peer key raises `{badmatch, error}`.
Use `x448/2` for a binary result or the atom `error`.
""".
-spec curve448(Scalar, Coordinate) -> SharedCoordinate when
    Scalar :: scalar(), Coordinate :: coordinate(), SharedCoordinate :: non_neg_integer().
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

-doc """
Derive a 56-byte X448 public key from a secret scalar.
The scalar is clamped by the native X448 operation.
""".
-spec x448(Secret) -> PublicKey when
    Secret :: x448_secret_key(), PublicKey :: x448_public_key().
x448(K) when
    is_binary(K) andalso
        byte_size(K) =:= ?X448_PRIVATE_BYTES
->
    libdecaf_nif:x448_derive_public_key(K).

-doc """
Compute an X448 shared secret with the secret scalar first and peer public key second.
Return `error` when the native operation rejects a peer key, including low-order
inputs producing an all-zero shared secret. Both keys must have 56 bytes.
""".
-spec x448(Secret, PeerPublicKey) -> SharedSecret when
    Secret :: x448_secret_key(), PeerPublicKey :: x448_public_key(), SharedSecret :: x448_shared_secret() | error.
x448(K, U) when
    is_binary(K) andalso
        byte_size(K) =:= ?X448_PRIVATE_BYTES andalso
        is_binary(U) andalso
        byte_size(U) =:= ?X448_PUBLIC_BYTES
->
    libdecaf_nif:x448(U, K).

-doc """
Generate a random X448 keypair `{PublicKey, SecretScalar}`.
The secret scalar contains 56 random bytes from `crypto:strong_rand_bytes/1`.
""".
-spec x448_keypair() -> Keypair when
    Keypair :: x448_keypair().
x448_keypair() ->
    x448_keypair(crypto:strong_rand_bytes(?X448_PRIVATE_BYTES)).

-doc """
Derive an X448 keypair `{PublicKey, SecretScalar}` from the supplied scalar.
The returned scalar bytes are the supplied bytes; clamping happens inside X448.
""".
-spec x448_keypair(Secret) -> Keypair when
    Secret :: x448_secret_key(), Keypair :: x448_keypair().
x448_keypair(Secret) when
    is_binary(Secret) andalso
        byte_size(Secret) =:= ?X448_PRIVATE_BYTES
->
    {x448(Secret), Secret}.
