%%%-----------------------------------------------------------------------------
%%% Internal functions
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
