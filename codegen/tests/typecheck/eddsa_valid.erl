%%% % @format
-module(eddsa_valid).
-typing([eqwalizer]).
-export([
    encoded/0,
    keypair/0
]).

-spec encoded() -> Valid when Valid :: boolean().
encoded() ->
    {Public, SigningKey} = libdecaf_curve25519:eddsa_keypair(),
    S0 = libdecaf_curve25519:ed25519ph_sign_init(SigningKey, <<"context">>),
    S1 = libdecaf_nif:ed25519ph_sign_update(S0, [<<"message">>]),
    Signature = libdecaf_curve25519:ed25519ph_sign_final(S1),
    V0 = libdecaf_nif:ed25519ph_verify_init(Signature, Public, <<"context">>),
    V1 = libdecaf_curve25519:ed25519ph_verify_update(V0, <<"message">>),
    libdecaf_nif:ed25519ph_verify_final(V1).

-spec keypair() -> Valid when Valid :: boolean().
keypair() ->
    Keypair = libdecaf_curve448:keypair_random(),
    Public = libdecaf_curve448:keypair_extract_public_key(Keypair),
    S0 = libdecaf_nif:ed448ph_keypair_sign_init(Keypair),
    S1 = libdecaf_curve448:ed448ph_sign_update(S0, <<"message">>),
    Signature = libdecaf_nif:ed448ph_sign_final(S1),
    V0 = libdecaf_curve448:ed448ph_verify_init(Signature, Public),
    V1 = libdecaf_nif:ed448ph_verify_update(V0, [<<"message">>]),
    libdecaf_curve448:ed448ph_verify_final(V1).
