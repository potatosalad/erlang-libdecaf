"""High-level EdDSA/ECDH contracts, implemented entirely through existing NIFs."""

from dataclasses import dataclass
from textwrap import fill

from .functions import Argument, Function


@dataclass(frozen=True)
class Curve:
    name: str
    key_bytes: int


SIGNATURE_CURVES = (Curve("ed25519", 32), Curve("ed448", 57))
AGREEMENT_CURVES = (Curve("x25519", 32), Curve("x448", 56))


@dataclass(frozen=True)
class Variant:
    name: str
    curve: str
    prehash: bool = False

    @property
    def has_context(self):
        return self.name != "ed25519"


VARIANTS = (
    Variant("ed25519", "ed25519"),
    Variant("ed25519ctx", "ed25519"),
    Variant("ed25519ph", "ed25519", prehash=True),
    Variant("ed448", "ed448"),
    Variant("ed448ph", "ed448", prehash=True),
)


@dataclass(frozen=True)
class Type:
    name: str
    definition: str
    doc: str
    opaque: bool = False


@dataclass(frozen=True)
class PublicKeyFunction(Function):
    overloads: tuple[Function, ...] = ()

    @property
    def spec(self):
        if not self.overloads:
            return super().spec
        return ";\n".join(f.spec if index == 0 else f.spec.removeprefix(self.name) for index, f in enumerate(self.overloads))


def types():
    result = [
        Type("ecdh_algorithm", "x25519 | x448", "An ECDH algorithm; its secret scalar is distinct from an EdDSA seed."),
        Type("eddsa_algorithm", "ed25519 | ed448", "The base curve used to generate an EdDSA keypair."),
        Type("eddsa_context", "binary()", "An operation-specific context of at most 255 bytes; omitted contexts are empty."),
        Type("message", "iodata()", "Original message bytes. Prehash variants compute the prehash internally."),
    ]
    for curve in SIGNATURE_CURVES:
        name, size = curve.name, curve.key_bytes
        for suffix in ("secret_key", "public_key", "signing_key", "signature"):
            result.append(
                Type(
                    f"{name}_{suffix}",
                    f"libdecaf_nif:{name}_{suffix}()",
                    {
                        "secret_key": f"The original {size}-byte {name} secret seed.",
                        "public_key": f"A {size}-byte {name} public key.",
                        "signing_key": f"An encoded {size * 2}-byte signing key: seed followed by its matching public key.",
                        "signature": f"A {size * 2}-byte {name} signature.",
                    }[suffix],
                )
            )
        result.extend(
            [
                Type(
                    f"{name}_keypair_state",
                    f"{{{name}_keypair, libdecaf_nif:{name}_keypair()}}",
                    f"An opaque {name} keypair wrapping a native resource; it contains no signature context.",
                    True,
                ),
                Type(
                    f"{name}_keypair",
                    f"{{{name}_public_key(), {name}_secret_key() | {name}_signing_key()}}",
                    "An extracted public/seed pair, or a legacy curve-module public/encoded-signing-key pair.",
                ),
                Type(
                    f"{name}_secret_key_compat",
                    f"{name}_secret_key() | {name}_signing_key() | {name}_keypair() | {name}_keypair_state()",
                    f"Accepted {name} signing inputs. Supplied seed/public-key pairs must match.",
                ),
                Type(
                    f"{name}_public_key_compat",
                    f"{name}_public_key() | {name}_keypair() | {name}_keypair_state()",
                    f"A {name} public key or a keypair from which to extract it.",
                ),
            ]
        )
        for operation in ("sign", "verify"):
            result.append(
                Type(
                    f"{name}ph_{operation}_state",
                    f"{{{name}ph_{operation}, libdecaf_nif:{name}ph_{operation}_state()}}",
                    f"An immutable {name}ph {operation} state, distinct from the other curve and operation.",
                    True,
                )
            )
            parameter_type = "secret_key_compat" if operation == "sign" else "public_key_compat"
            variants = [variant for variant in VARIANTS if variant.curve == name]
            for init in (False, True):
                forms = []
                for variant in variants:
                    if init and not variant.prehash:
                        continue
                    forms.append(f"{{{variant.name}, {name}_{parameter_type}()}}")
                    if variant.has_context:
                        forms.append(f"{{{variant.name}, {name}_{parameter_type}(), eddsa_context()}}")
                suffix = "init_parameters" if init else "parameters"
                result.append(
                    Type(
                        f"{name}_{operation}_{suffix}",
                        " | ".join(forms),
                        f"{name} {operation} parameters" + (" restricted to the prehash variant." if init else "."),
                    )
                )

    for suffix, doc in (
        ("keypair_state", "An opaque native EdDSA keypair for either base curve."),
        ("keypair", "An EdDSA public/secret pair; newly extracted pairs contain the original seed."),
        ("secret_key", "An original Ed25519 or Ed448 secret seed."),
        ("signing_key", "A legacy encoded EdDSA seed/public-key signing key."),
        ("public_key", "An Ed25519 or Ed448 public-key encoding."),
        ("signature", "An Ed25519 or Ed448 signature encoding."),
        ("sign_parameters", "One-shot EdDSA algorithm, signing key, and optional context."),
        ("sign_init_parameters", "Streaming signing parameters, restricted to Ed25519ph or Ed448ph."),
        ("verify_parameters", "One-shot EdDSA algorithm, verification key, and optional context."),
        ("verify_init_parameters", "Streaming verification parameters, restricted to Ed25519ph or Ed448ph."),
    ):
        result.append(Type(f"eddsa_{suffix}", f"ed25519_{suffix}() | ed448_{suffix}()", doc))
    for operation in ("sign", "verify"):
        result.append(
            Type(
                f"eddsa_{operation}_state",
                f"ed25519ph_{operation}_state() | ed448ph_{operation}_state()",
                f"An immutable streaming EdDSA {operation} state.",
            )
        )

    for curve in AGREEMENT_CURVES:
        name, size = curve.name, curve.key_bytes
        for suffix, native in (("secret_key", "scalar"), ("public_key", "public_key"), ("shared_secret", "shared_secret")):
            result.append(
                Type(f"{name}_{suffix}", f"libdecaf_nif:{name}_{native}()", f"A {size}-byte {name} {suffix.replace('_', ' ')}.")
            )
        result.extend(
            [
                Type(
                    f"{name}_keypair",
                    f"{{{name}_keypair, {name}_public_key(), {name}_secret_key()}}",
                    f"An opaque {name} public/secret keypair stored as Erlang binaries.",
                    True,
                ),
                Type(
                    f"{name}_keypair_bytes",
                    f"{{{name}_public_key(), {name}_secret_key()}}",
                    "A curve-module public/secret scalar pair.",
                ),
            ]
        )
        for suffix in ("secret_key", "public_key"):
            result.append(
                Type(
                    f"{name}_{suffix}_compat",
                    f"{name}_{suffix}() | {name}_keypair() | {name}_keypair_bytes()",
                    f"A {name} {suffix.replace('_', ' ')} or a keypair supplying it.",
                )
            )
    for suffix in ("keypair", "public_key", "secret_key", "shared_secret"):
        result.append(
            Type(f"ecdh_{suffix}", f"x25519_{suffix}() | x448_{suffix}()", f"An X25519 or X448 {suffix.replace('_', ' ')}.")
        )
    return tuple(sorted(result, key=lambda item: item.name))


def functions():
    result = []

    def add(name, arguments, returns, doc, result_name="Result", overloads=()):
        family = name.split("_", 1)[0]
        doc = "\n\n".join(
            paragraph if paragraph.startswith("```") else fill(paragraph, width=100) for paragraph in doc.split("\n\n")
        )
        arguments = tuple(Argument(*arg) for arg in arguments)
        alternatives = tuple(
            Function(name, tuple(Argument(*arg) for arg in args), ret, doc, family, result_name=result_name)
            for args, ret in overloads
        )
        result.append(
            PublicKeyFunction(
                name,
                arguments,
                returns,
                doc,
                f"{family.upper() if family == 'ecdh' else 'EdDSA'} API",
                family=family,
                result_name=result_name,
                overloads=alternatives,
            )
        )

    for family, curves, state_suffix in (("ecdh", AGREEMENT_CURVES, "keypair"), ("eddsa", SIGNATURE_CURVES, "keypair_state")):
        title = "ECDH" if family == "ecdh" else "EdDSA"
        secret = "scalar" if family == "ecdh" else "seed"
        example_type = curves[0].name
        add(
            f"{family}_keypair",
            [("Type", f"{family}_algorithm()")],
            f"{family}_{state_suffix}()",
            f"Generate a random {title} keypair.\n\n"
            f"Keep the opaque keypair for repeated operations; extract bytes when needed.\n\n"
            f"```erlang\nKeypair = libdecaf:{family}_keypair({example_type}),\nPublicKey = libdecaf:{family}_keypair_extract_public_key(Keypair).\n```",
            "Keypair",
            [([("Type", c.name)], f"{c.name}_{state_suffix}()") for c in curves],
        )
        add(
            f"{family}_keypair",
            [("Type", f"{family}_algorithm()"), ("SecretKey", f"{family}_secret_key()")],
            f"{family}_{state_suffix}()",
            f"Derive an {title} keypair from an existing secret {secret}.\n\n"
            + (
                "Ed25519 uses a 32-byte seed; Ed448 uses a 57-byte seed. Contexts belong to signing/verification parameters, not keypairs."
                if family == "eddsa"
                else "X25519 uses 32 bytes; X448 uses 56. The scalar is clamped inside the native operation; extraction returns the supplied bytes."
            )
            + f"\n\n```erlang\nSecretKey = crypto:strong_rand_bytes(32),\nKeypair = libdecaf:{family}_keypair({example_type}, SecretKey),\nSecretKey = libdecaf:{family}_keypair_extract_secret_key(Keypair).\n```",
            "Keypair",
            [([("Type", c.name), ("SecretKey", f"{c.name}_secret_key()")], f"{c.name}_{state_suffix}()") for c in curves],
        )
        for suffix, ret, description in (
            ("", f"{{{family}_public_key(), {family}_secret_key()}}", "Return `{PublicKey, SecretKey}` in that order."),
            ("_public_key", f"{family}_public_key()", "Extract the public-key bytes."),
            ("_secret_key", f"{family}_secret_key()", f"Extract the original secret {secret} bytes."),
        ):
            add(
                f"{family}_keypair_extract{suffix}",
                [("Keypair", f"{family}_{state_suffix}()")],
                ret,
                description
                + (
                    "\nFor EdDSA, the secret is the original seed, not the encoded seed/public-key signing key."
                    if family == "eddsa"
                    else ""
                ),
                "Keys" if not suffix else "PublicKey" if suffix == "_public_key" else "SecretKey",
                [
                    (
                        [("Keypair", f"{c.name}_{state_suffix}()")],
                        f"{{{c.name}_public_key(), {c.name}_secret_key()}}" if not suffix else f"{c.name}{suffix}()",
                    )
                    for c in curves
                ],
            )

    add(
        "ecdh_shared_secret",
        [
            ("Type", "ecdh_algorithm()"),
            ("SecretKey", "x25519_secret_key_compat() | x448_secret_key_compat()"),
            ("PublicKey", "x25519_public_key_compat() | x448_public_key_compat()"),
        ],
        "ecdh_shared_secret() | error",
        "Compute the raw ECDH shared secret with the local secret first and peer public key second.\n\n"
        "Either argument may be an opaque keypair or a curve-module `{PublicKey, SecretScalar}` pair. "
        "Keypair curves must match `Type`. Return `error` when the native operation rejects the peer, including an all-zero shared secret. "
        "Malformed arguments raise `badarg`. Protocols should apply their specified key derivation to the raw secret.\n\n"
        "```erlang\nAlice = libdecaf:ecdh_keypair(x25519),\nBob = libdecaf:ecdh_keypair(x25519),\n"
        "Shared = libdecaf:ecdh_shared_secret(x25519, Alice, Bob),\nShared = libdecaf:ecdh_shared_secret(x25519, Bob, Alice).\n```",
        "SharedSecret",
        [
            (
                [("Type", c.name), ("SecretKey", f"{c.name}_secret_key_compat()"), ("PublicKey", f"{c.name}_public_key_compat()")],
                f"{c.name}_shared_secret() | error",
            )
            for c in AGREEMENT_CURVES
        ],
    )

    key_doc = (
        "Signing keys may be original seeds, encoded `Seed || PublicKey` binaries, "
        "public/secret pairs, or opaque keypairs. Encoded keys and pairs are checked for matching public keys. "
        "Messages accept iodata; pass the original message even for prehash variants. "
        "Contexts are binaries of at most 255 bytes and default to `<<>>`. Pure Ed25519 accepts no context; "
        "Ed25519ctx with an empty context is distinct from pure Ed25519."
    )
    add(
        "eddsa_sign",
        [("Parameters", "eddsa_sign_parameters()"), ("Message", "message()")],
        "eddsa_signature()",
        "Sign a message using `{Algorithm, Key}` or `{Algorithm, Key, Context}`.\n\n"
        + key_doc
        + '\n\n```erlang\nKeypair = libdecaf:eddsa_keypair(ed25519),\nSignature = libdecaf:eddsa_sign({ed25519, Keypair}, <<"message">>),\n'
        'PublicKey = libdecaf:eddsa_keypair_extract_public_key(Keypair),\ntrue = libdecaf:eddsa_verify({ed25519, PublicKey}, Signature, <<"message">>).\n```',
        "Signature",
        [
            ([("Parameters", f"{c.name}_sign_parameters()"), ("Message", "message()")], f"{c.name}_signature()")
            for c in SIGNATURE_CURVES
        ],
    )
    add(
        "eddsa_verify",
        [("Parameters", "eddsa_verify_parameters()"), ("Signature", "eddsa_signature()"), ("Message", "message()")],
        "boolean()",
        "Verify a signature over an original message using the same algorithm and context as signing.\n\n"
        "Parameters contain a public key, public/secret pair, or opaque keypair. Return `false` for a correctly sized signature "
        "that fails verification; malformed keys, signatures, or parameters raise `badarg`. Message input accepts iodata.\n\n"
        '```erlang\nKeypair = libdecaf:eddsa_keypair(ed448),\nSignature = libdecaf:eddsa_sign({ed448, Keypair, <<"protocol/v1">>}, <<"message">>),\n'
        'true = libdecaf:eddsa_verify({ed448, Keypair, <<"protocol/v1">>}, Signature, <<"message">>).\n```',
        "Valid",
        [
            (
                [("Parameters", f"{c.name}_verify_parameters()"), ("Signature", f"{c.name}_signature()"), ("Message", "message()")],
                "boolean()",
            )
            for c in SIGNATURE_CURVES
        ],
    )

    for operation in ("sign", "verify"):
        signing = operation == "sign"
        args = [("Parameters", f"eddsa_{operation}_init_parameters()")]
        if not signing:
            args.append(("Signature", "eddsa_signature()"))
        example = (
            "Keypair = libdecaf:eddsa_keypair(ed25519),\n"
            'S0 = libdecaf:eddsa_sign_init({ed25519ph, Keypair, <<"protocol/v1">>}),\n'
            'S1 = libdecaf:eddsa_sign_update(S0, [<<"hello ">>, <<"world">>]),\n'
            "Signature = libdecaf:eddsa_sign_final(S1)"
        )
        if not signing:
            example += (
                ',\nV0 = libdecaf:eddsa_verify_init({ed25519ph, Keypair, <<"protocol/v1">>}, Signature),\n'
                'V1 = libdecaf:eddsa_verify_update(V0, <<"hello world">>),\ntrue = libdecaf:eddsa_verify_final(V1)'
            )
        add(
            f"eddsa_{operation}_init",
            args,
            f"eddsa_{operation}_state()",
            f"Start streaming {'signing' if signing else 'verification'} with Ed25519ph or Ed448ph.\n\n"
            + (
                key_doc
                if signing
                else "Use `{Algorithm, PublicKeyOrKeypair}` with an optional third context field, matching the signing parameters."
            )
            + "\nThe native state retains the key, context"
            + ("" if signing else ", signature")
            + " and prehash. "
            "Updates and finalization leave their input reusable. Pure Ed25519, Ed25519ctx, and Ed448 are one-shot only.\n\n"
            f"```erlang\n{example}.\n```",
            "State",
            [
                (
                    [("Parameters", f"{c.name}_{operation}_init_parameters()")]
                    + ([] if signing else [("Signature", f"{c.name}_signature()")]),
                    f"{c.name}ph_{operation}_state()",
                )
                for c in SIGNATURE_CURVES
            ],
        )
        add(
            f"eddsa_{operation}_update",
            [("State", f"eddsa_{operation}_state()"), ("Message", "message()")],
            f"eddsa_{operation}_state()",
            f"Add another original-message chunk and return a new {'signing' if signing else 'verification'} state.\n\n"
            "Chunks accept iodata. Large updates yield to the scheduler; completed updates do not retain the input chunks. "
            "The original state remains reusable for branching. Signing and verification states are distinct.",
            "NextState",
            [
                ([("State", f"{c.name}ph_{operation}_state()"), ("Message", "message()")], f"{c.name}ph_{operation}_state()")
                for c in SIGNATURE_CURVES
            ],
        )
        add(
            f"eddsa_{operation}_final",
            [("State", f"eddsa_{operation}_state()")],
            "eddsa_signature()" if signing else "boolean()",
            (
                "Sign the accumulated original message using the retained keypair and context."
                if signing
                else "Verify the accumulated original message against the retained signature, key, and context."
            )
            + "\nThe input state is unchanged; repeated finalization returns the same result. "
            + (
                "The signature matches one-shot signing with the same parameters."
                if signing
                else "Return `false` if verification fails."
            ),
            "Signature" if signing else "Valid",
            [
                ([("State", f"{c.name}ph_{operation}_state()")], f"{c.name}_signature()" if signing else "boolean()")
                for c in SIGNATURE_CURVES
            ],
        )
    return tuple(sorted(result, key=lambda item: (item.name, item.arity)))
