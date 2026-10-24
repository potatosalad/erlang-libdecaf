%%% % @format
-module(public_key_valid).
-typing([eqwalizer]).
-export([
    ecdh/0,
    encoded/0,
    streaming/0
]).

-spec ecdh() -> Secret when Secret :: libdecaf:x25519_shared_secret() | error.
ecdh() ->
    Alice = libdecaf:ecdh_keypair(x25519),
    Bob = libdecaf:ecdh_keypair(x25519),
    BobPublic = libdecaf:ecdh_keypair_extract_public_key(Bob),
    libdecaf:ecdh_shared_secret(x25519, Alice, BobPublic).

-spec encoded() -> Signature when Signature :: libdecaf:ed448_signature().
encoded() ->
    Keypair = libdecaf:eddsa_keypair(ed448),
    {Public, Seed} = libdecaf:eddsa_keypair_extract(Keypair),
    SigningKey = <<Seed/binary, Public/binary>>,
    Signature = libdecaf:eddsa_sign({ed448, SigningKey, <<"context">>}, [<<"message">>]),
    true = libdecaf:eddsa_verify({ed448, {Public, Seed}, <<"context">>}, Signature, <<"message">>),
    Signature.

-spec streaming() -> Valid when Valid :: boolean().
streaming() ->
    Keypair = libdecaf:eddsa_keypair(ed25519),
    S0 = libdecaf:eddsa_sign_init({ed25519ph, Keypair}),
    S1 = libdecaf:eddsa_sign_update(S0, [<<"message">>]),
    Signature = libdecaf:eddsa_sign_final(S1),
    V0 = libdecaf:eddsa_verify_init({ed25519ph, Keypair}, Signature),
    V1 = libdecaf:eddsa_verify_update(V0, <<"message">>),
    libdecaf:eddsa_verify_final(V1).
