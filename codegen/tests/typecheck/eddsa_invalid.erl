%%% % @format
-module(eddsa_invalid).
-typing([eqwalizer]).
-export([
    crossed_curve/0,
    crossed_operation/0,
    crossed_parameter/0
]).

-spec crossed_curve() -> State when State :: libdecaf_nif:ed448ph_sign_state().
crossed_curve() ->
    Keypair = libdecaf_curve25519:keypair_random(),
    State = libdecaf_curve25519:ed25519ph_keypair_sign_init(Keypair),
    libdecaf_nif:ed448ph_sign_update(State, <<"message">>).

-spec crossed_operation() -> Valid when Valid :: boolean().
crossed_operation() ->
    Keypair = libdecaf_curve25519:keypair_random(),
    State = libdecaf_nif:ed25519ph_keypair_sign_init(Keypair),
    libdecaf_curve25519:ed25519ph_verify_final(State).

-spec crossed_parameter() -> State when State :: libdecaf_nif:ed25519ph_sign_state().
crossed_parameter() ->
    Keypair = libdecaf_curve25519:keypair_random(),
    libdecaf_nif:ed25519ph_sign_init(Keypair).
