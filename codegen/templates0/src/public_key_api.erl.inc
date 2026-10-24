~J{ macro contract(name, arity) }.
~J{ set function = ctx.public_key_function(name, arity) }.
-doc """
~J< function.doc >.
""".
-doc #{group => <<"~J< function.group >.">>}.
-spec ~J< function.spec >..
~J{ endmacro }.
%%%=============================================================================
%%% ECDH API functions
%%%=============================================================================

~J< contract('ecdh_keypair', 1) >.
~J{ for curve in ctx.agreement_curves }.
ecdh_keypair(~J< curve.name >.) ->
    ecdh_keypair(~J< curve.name >., crypto:strong_rand_bytes(~J< curve.key_bytes >.));
~J{ endfor }.
ecdh_keypair(_) ->
    erlang:error(badarg).

~J< contract('ecdh_keypair', 2) >.
~J{ for curve in ctx.agreement_curves }.
ecdh_keypair(~J< curve.name >., SecretKey = <<_:~J< curve.key_bytes >./binary>>) ->
    {~J< curve.name >._keypair, libdecaf_nif:~J< curve.name >._derive_public_key(SecretKey), SecretKey};
~J{ endfor }.
ecdh_keypair(_, _) ->
    erlang:error(badarg).

~J< contract('ecdh_keypair_extract', 1) >.
~J{ for curve in ctx.agreement_curves }.
ecdh_keypair_extract({~J< curve.name >._keypair, PublicKey = <<_:~J< curve.key_bytes >./binary>>, SecretKey = <<_:~J< curve.key_bytes >./binary>>}) ->
    {PublicKey, SecretKey};
~J{ endfor }.
ecdh_keypair_extract(_) ->
    erlang:error(badarg).

~J< contract('ecdh_keypair_extract_public_key', 1) >.
ecdh_keypair_extract_public_key(Keypair) ->
    {PublicKey, _SecretKey} = ecdh_keypair_extract(Keypair),
    PublicKey.

~J< contract('ecdh_keypair_extract_secret_key', 1) >.
ecdh_keypair_extract_secret_key(Keypair) ->
    {_PublicKey, SecretKey} = ecdh_keypair_extract(Keypair),
    SecretKey.

~J< contract('ecdh_shared_secret', 3) >.
~J{ for curve in ctx.agreement_curves }.
ecdh_shared_secret(~J< curve.name >., SecretKey, PublicKey) ->
    libdecaf_nif:~J< curve.name >.(ecdh_~J< curve.name >._public_key(PublicKey), ecdh_~J< curve.name >._secret_key(SecretKey));
~J{ endfor }.
ecdh_shared_secret(_, _, _) ->
    erlang:error(badarg).

%%%=============================================================================
%%% EdDSA API functions
%%%=============================================================================

~J< contract('eddsa_keypair', 1) >.
~J{ for curve in ctx.signature_curves }.
eddsa_keypair(~J< curve.name >.) ->
    eddsa_keypair(~J< curve.name >., crypto:strong_rand_bytes(~J< curve.key_bytes >.));
~J{ endfor }.
eddsa_keypair(_) ->
    erlang:error(badarg).

~J< contract('eddsa_keypair', 2) >.
~J{ for curve in ctx.signature_curves }.
eddsa_keypair(~J< curve.name >., SecretKey = <<_:~J< curve.key_bytes >./binary>>) ->
    {~J< curve.name >._keypair, libdecaf_nif:~J< curve.name >._derive_keypair(SecretKey)};
~J{ endfor }.
eddsa_keypair(_, _) ->
    erlang:error(badarg).

~J< contract('eddsa_keypair_extract', 1) >.
eddsa_keypair_extract(Keypair) ->
    {eddsa_keypair_extract_public_key(Keypair), eddsa_keypair_extract_secret_key(Keypair)}.

~J< contract('eddsa_keypair_extract_public_key', 1) >.
~J{ for curve in ctx.signature_curves }.
eddsa_keypair_extract_public_key({~J< curve.name >._keypair, Keypair}) ->
    libdecaf_nif:~J< curve.name >._keypair_extract_public_key(Keypair);
~J{ endfor }.
eddsa_keypair_extract_public_key(_) ->
    erlang:error(badarg).

~J< contract('eddsa_keypair_extract_secret_key', 1) >.
~J{ for curve in ctx.signature_curves }.
eddsa_keypair_extract_secret_key({~J< curve.name >._keypair, Keypair}) ->
    libdecaf_nif:~J< curve.name >._keypair_extract_private_key(Keypair);
~J{ endfor }.
eddsa_keypair_extract_secret_key(_) ->
    erlang:error(badarg).

~J< contract('eddsa_sign', 2) >.
~J{ for variant in ctx.signature_variants }.
~J{ if variant.has_context }.
eddsa_sign({~J< variant.name >., Key}, Message) ->
    eddsa_sign({~J< variant.name >., Key, <<>>}, Message);
eddsa_sign({~J< variant.name >., Key, Context}, Message) when is_binary(Context), byte_size(Context) =< 255 ->
~J{ else }.
eddsa_sign({~J< variant.name >., Key}, Message) ->
~J{ endif }.
~J{ if variant.prehash }.
    libdecaf_nif:~J< variant.curve >._keypair_sign_prehash(eddsa_~J< variant.curve >._keypair(Key), iolist_to_binary(Message), Context);
~J{ else }.
    libdecaf_nif:~J< variant.curve >._keypair_sign(eddsa_~J< variant.curve >._keypair(Key), iolist_to_binary(Message), 0, ~J< 'Context' if variant.has_context else 'no_context' >.);
~J{ endif }.
~J{ endfor }.
eddsa_sign(_, _) ->
    erlang:error(badarg).

~J< contract('eddsa_sign_final', 1) >.
~J{ for curve in ctx.signature_curves }.
eddsa_sign_final({~J< curve.name >.ph_sign, State}) ->
    libdecaf_nif:~J< curve.name >.ph_sign_final(State);
~J{ endfor }.
eddsa_sign_final(_) ->
    erlang:error(badarg).

~J< contract('eddsa_sign_init', 1) >.
~J{ for curve in ctx.signature_curves }.
eddsa_sign_init({~J< curve.name >.ph, Key}) ->
    eddsa_sign_init({~J< curve.name >.ph, Key, <<>>});
eddsa_sign_init({~J< curve.name >.ph, Key, Context}) when is_binary(Context), byte_size(Context) =< 255 ->
    {~J< curve.name >.ph_sign, libdecaf_nif:~J< curve.name >.ph_keypair_sign_init(eddsa_~J< curve.name >._keypair(Key), Context)};
~J{ endfor }.
eddsa_sign_init(_) ->
    erlang:error(badarg).

~J< contract('eddsa_sign_update', 2) >.
~J{ for curve in ctx.signature_curves }.
eddsa_sign_update({~J< curve.name >.ph_sign, State}, Message) ->
    {~J< curve.name >.ph_sign, libdecaf_nif:~J< curve.name >.ph_sign_update(State, Message)};
~J{ endfor }.
eddsa_sign_update(_, _) ->
    erlang:error(badarg).

~J< contract('eddsa_verify', 3) >.
~J{ for variant in ctx.signature_variants }.
~J{ if variant.has_context }.
eddsa_verify({~J< variant.name >., Key}, Signature, Message) ->
    eddsa_verify({~J< variant.name >., Key, <<>>}, Signature, Message);
eddsa_verify({~J< variant.name >., Key, Context}, Signature, Message) when is_binary(Context), byte_size(Context) =< 255 ->
~J{ else }.
eddsa_verify({~J< variant.name >., Key}, Signature, Message) ->
~J{ endif }.
~J{ if variant.prehash }.
    libdecaf_nif:~J< variant.curve >._verify_prehash(Signature, eddsa_~J< variant.curve >._public_key(Key), iolist_to_binary(Message), Context);
~J{ else }.
    libdecaf_nif:~J< variant.curve >._verify(Signature, eddsa_~J< variant.curve >._public_key(Key), iolist_to_binary(Message), 0, ~J< 'Context' if variant.has_context else 'no_context' >.);
~J{ endif }.
~J{ endfor }.
eddsa_verify(_, _, _) ->
    erlang:error(badarg).

~J< contract('eddsa_verify_final', 1) >.
~J{ for curve in ctx.signature_curves }.
eddsa_verify_final({~J< curve.name >.ph_verify, State}) ->
    libdecaf_nif:~J< curve.name >.ph_verify_final(State);
~J{ endfor }.
eddsa_verify_final(_) ->
    erlang:error(badarg).

~J< contract('eddsa_verify_init', 2) >.
~J{ for curve in ctx.signature_curves }.
eddsa_verify_init({~J< curve.name >.ph, Key}, Signature) ->
    eddsa_verify_init({~J< curve.name >.ph, Key, <<>>}, Signature);
eddsa_verify_init({~J< curve.name >.ph, Key, Context}, Signature) when is_binary(Context), byte_size(Context) =< 255 ->
    {~J< curve.name >.ph_verify, libdecaf_nif:~J< curve.name >.ph_verify_init(Signature, eddsa_~J< curve.name >._public_key(Key), Context)};
~J{ endfor }.
eddsa_verify_init(_, _) ->
    erlang:error(badarg).

~J< contract('eddsa_verify_update', 2) >.
~J{ for curve in ctx.signature_curves }.
eddsa_verify_update({~J< curve.name >.ph_verify, State}, Message) ->
    {~J< curve.name >.ph_verify, libdecaf_nif:~J< curve.name >.ph_verify_update(State, Message)};
~J{ endfor }.
eddsa_verify_update(_, _) ->
    erlang:error(badarg).

%%%-----------------------------------------------------------------------------
%%% Internal public-key functions
%%%-----------------------------------------------------------------------------

~J{ for curve in ctx.agreement_curves }.
~J{ for part in ('public_key', 'secret_key') }.
-spec ecdh_~J< curve.name >._~J< part >.(Key) -> Bytes when Key :: ~J< curve.name >._~J< part >._compat(), Bytes :: ~J< curve.name >._~J< part >.().
ecdh_~J< curve.name >._~J< part >.(Bytes = <<_:~J< curve.key_bytes >./binary>>) ->
    Bytes;
ecdh_~J< curve.name >._~J< part >.({~J< curve.name >._keypair, ~J< 'Bytes = ' if part == 'public_key' else '' >.<<_:~J< curve.key_bytes >./binary>>, ~J< 'Bytes = ' if part == 'secret_key' else '' >.<<_:~J< curve.key_bytes >./binary>>}) ->
    Bytes;
ecdh_~J< curve.name >._~J< part >.({~J< 'Bytes = ' if part == 'public_key' else '' >.<<_:~J< curve.key_bytes >./binary>>, ~J< 'Bytes = ' if part == 'secret_key' else '' >.<<_:~J< curve.key_bytes >./binary>>}) ->
    Bytes;
ecdh_~J< curve.name >._~J< part >.(_) ->
    erlang:error(badarg).

~J{ endfor }.
~J{ endfor }.
~J{ for curve in ctx.signature_curves }.
-spec eddsa_~J< curve.name >._keypair(Key) -> Native when Key :: ~J< curve.name >._secret_key_compat(), Native :: libdecaf_nif:~J< curve.name >._keypair().
eddsa_~J< curve.name >._keypair({~J< curve.name >._keypair, Native}) ->
    Native;
eddsa_~J< curve.name >._keypair(Seed = <<_:~J< curve.key_bytes >./binary>>) ->
    libdecaf_nif:~J< curve.name >._derive_keypair(Seed);
eddsa_~J< curve.name >._keypair(<<Seed:~J< curve.key_bytes >./binary, PublicKey:~J< curve.key_bytes >./binary>>) ->
    Native = libdecaf_nif:~J< curve.name >._derive_keypair(Seed),
    case libdecaf_nif:~J< curve.name >._keypair_extract_public_key(Native) of
        PublicKey -> Native;
        _ -> erlang:error(badarg)
    end;
eddsa_~J< curve.name >._keypair({PublicKey = <<_:~J< curve.key_bytes >./binary>>, Seed = <<_:~J< curve.key_bytes >./binary>>}) ->
    eddsa_~J< curve.name >._keypair(<<Seed/binary, PublicKey/binary>>);
eddsa_~J< curve.name >._keypair({PublicKey = <<_:~J< curve.key_bytes >./binary>>, SigningKey = <<_:~J< curve.key_bytes >./binary, PublicKey:~J< curve.key_bytes >./binary>>}) ->
    eddsa_~J< curve.name >._keypair(SigningKey);
eddsa_~J< curve.name >._keypair(_) ->
    erlang:error(badarg).

-spec eddsa_~J< curve.name >._public_key(Key) -> PublicKey when Key :: ~J< curve.name >._public_key_compat(), PublicKey :: ~J< curve.name >._public_key().
eddsa_~J< curve.name >._public_key(PublicKey = <<_:~J< curve.key_bytes >./binary>>) ->
    PublicKey;
eddsa_~J< curve.name >._public_key({~J< curve.name >._keypair, Native}) ->
    libdecaf_nif:~J< curve.name >._keypair_extract_public_key(Native);
eddsa_~J< curve.name >._public_key({PublicKey = <<_:~J< curve.key_bytes >./binary>>, SecretKey}) ->
    _ = eddsa_~J< curve.name >._keypair({PublicKey, SecretKey}),
    PublicKey;
eddsa_~J< curve.name >._public_key(_) ->
    erlang:error(badarg).

~J{ endfor }.
