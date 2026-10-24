%%% % @format
-module(public_key_invalid).
-typing([eqwalizer]).
-export([
    crossed_ecdh/0,
    crossed_operation/0,
    crossed_signing_key/0,
    wrong_ecdh_state/0,
    pure_streaming/0,
    pure_context/0
]).

-spec crossed_ecdh() -> Secret when Secret :: libdecaf:ecdh_shared_secret() | error.
crossed_ecdh() ->
    Keypair = libdecaf:ecdh_keypair(x448),
    Peer = libdecaf:ecdh_keypair(x25519),
    libdecaf:ecdh_shared_secret(x25519, Keypair, Peer).

-spec wrong_ecdh_state() -> Keypair when Keypair :: libdecaf:x25519_keypair().
wrong_ecdh_state() ->
    libdecaf:ecdh_keypair(x448).

-spec crossed_operation() -> Valid when Valid :: boolean().
crossed_operation() ->
    Keypair = libdecaf:eddsa_keypair(ed25519),
    State = libdecaf:eddsa_sign_init({ed25519ph, Keypair}),
    libdecaf:eddsa_verify_final(State).

-spec crossed_signing_key() -> Signature when Signature :: libdecaf:eddsa_signature().
crossed_signing_key() ->
    Keypair = libdecaf:eddsa_keypair(ed448),
    libdecaf:eddsa_sign({ed25519, Keypair}, <<"message">>).

-spec pure_streaming() -> State when State :: libdecaf:eddsa_sign_state().
pure_streaming() ->
    Keypair = libdecaf:eddsa_keypair(ed25519),
    libdecaf:eddsa_sign_init({ed25519, Keypair}).

-spec pure_context() -> Signature when Signature :: libdecaf:eddsa_signature().
pure_context() ->
    Keypair = libdecaf:eddsa_keypair(ed25519),
    libdecaf:eddsa_sign({ed25519, Keypair, <<"context">>}, <<"message">>).
