"""Documentation and type contracts for libdecaf's Erlang NIF interface."""

from dataclasses import dataclass

from ..schema import NIF as NIFSchema
from .groups import PRIME_ORDER_GROUPS


@dataclass(frozen=True)
class Argument:
    name: str
    type: str


@dataclass(frozen=True)
class Function:
    name: str
    arguments: tuple[Argument, ...]
    returns: str
    doc: str
    group: str
    family: str | None = None
    operation: str | None = None
    algorithms: tuple[str, ...] = ()
    result_name: str = "Result"

    @property
    def arity(self) -> int:
        return len(self.arguments)

    @property
    def parameters(self) -> str:
        return ", ".join("_" + argument.name for argument in self.arguments)

    @property
    def spec(self) -> str:
        arguments = ", ".join(argument.name for argument in self.arguments)
        constraints = [f"{argument.name} :: {argument.type}" for argument in self.arguments]
        constraints.append(f"{self.result_name} :: {self.returns}")
        return f"{self.name}({arguments}) -> {self.result_name} when\n    " + ", ".join(constraints)

    @property
    def c_name(self) -> str:
        return f"libdecaf_nif_{self.name}_{self.arity}"


@dataclass(frozen=True)
class XOFGroup:
    name: str
    algorithms: tuple[str, ...]

    @property
    def state_type(self) -> str:
        return f"{self.name}_state"

    @property
    def algorithm_type(self) -> str:
        return f"{self.name}_algorithm"


def xof_groups(schema: NIFSchema) -> tuple[XOFGroup, ...]:
    result = []
    for group in sorted({profile.group for profile in schema.xof.values()}):
        algorithms = tuple(sorted(name for name, profile in schema.xof.items() if profile.group == group))
        result.append(XOFGroup(f"xof_{group}", algorithms))
    return tuple(result)


def xof_functions(schema: NIFSchema) -> tuple[Function, ...]:
    result = []

    def add(group, operation, arguments, returns, doc):
        name = group.name + ("" if operation == "once" else f"_{operation}")
        result.append(
            Function(
                name,
                tuple(Argument(*arg) for arg in arguments),
                returns,
                doc,
                "XOF API",
                "xof",
                operation,
                group.algorithms,
                {"init": "State", "update": "NewState"}.get(operation, "Output"),
            )
        )

    for group in xof_groups(schema):
        state = f"{group.state_type}()"
        algorithm = [("Algorithm", f"{group.algorithm_type}()")]
        basic = algorithm + [("Input", "iodata()"), ("Length", "non_neg_integer()")]
        add(group, "once", basic, "binary()", "Hash iodata and return `Length` XOF bytes using default parameters.")
        add(group, "init", algorithm, state, "Create an immutable native XOF state using default parameters.")
        add(
            group,
            "update",
            [("State", state), ("Input", "iodata()")],
            state,
            "Absorb iodata and return a new state in this XOF group. The input state remains reusable.",
        )
        add(
            group,
            "final",
            [("State", state), ("Length", "non_neg_integer()")],
            "binary()",
            "Return `Length` XOF bytes without changing the state.",
        )
        profile = schema.xof[group.algorithms[0]]
        if profile.cshake_rate is not None:
            extra = [("FunctionName", "iodata()"), ("Customization", "iodata()")]
            add(
                group,
                "once",
                basic + extra,
                "binary()",
                "Hash iodata with SP 800-185 function-name and customization strings.\nBoth empty strings produce the corresponding SHAKE output.",
            )
            add(
                group,
                "init",
                algorithm + extra,
                state,
                "Create a cSHAKE state with SP 800-185 function-name and customization strings.",
            )
        if profile.turbo_rate is not None:
            extra = [("Domain", "1..127")]
            add(group, "once", basic + extra, "binary()", "Hash iodata using a TurboSHAKE domain byte in `1..127`.")
            add(group, "init", algorithm + extra, state, "Create a TurboSHAKE state with a domain byte in `1..127`.")
        if profile.kt_rate is not None:
            extra = [("Customization", "iodata()")]
            add(
                group,
                "once",
                basic + extra,
                "binary()",
                "Hash iodata using a KangarooTwelve customization string appended per RFC 9861.",
            )
            add(
                group,
                "final",
                [("State", state), ("Length", "non_neg_integer()")] + extra,
                "binary()",
                "Finalize KangarooTwelve with a customization string. The input state remains reusable.",
            )
    return tuple(sorted(result, key=lambda function: (function.name, function.arity)))


def kmac_functions(schema: NIFSchema) -> tuple[Function, ...]:
    if not schema.kmac:
        return ()
    result = []

    def add(name, arguments, returns, doc, result_name):
        result.append(
            Function(
                name,
                tuple(Argument(*argument) for argument in arguments),
                returns,
                doc,
                "KMAC API",
                family="kmac",
                algorithms=tuple(sorted(schema.kmac)),
                result_name=result_name,
            )
        )

    basic = [("Type", "kmac_algorithm()"), ("Key", "iodata()"), ("Data", "iodata()"), ("Length", "non_neg_integer()")]
    custom = [("Customization", "iodata()")]
    init = [("Type", "kmac_algorithm()"), ("Key", "iodata()")]
    add(
        "kmac",
        basic,
        "binary()",
        "Compute a KMAC128 or KMAC256 tag with empty customization.\n\n"
        "`Length` is the requested number of bytes, including zero. KMAC encodes this\n"
        "length into the computation: requesting fewer bytes changes the tag rather\n"
        "than truncating a longer result. Keys and messages accept iodata.\n"
        "The primitive accepts any key length; NIST-approved uses require at least\n"
        "16 key bytes for KMAC128 or 32 for KMAC256 (SP 800-185r1 IPD, Section 9.4.1).",
        "Tag",
    )
    add(
        "kmac",
        basic + custom,
        "binary()",
        "Compute a KMAC tag using SP 800-185 customization iodata.\n\n"
        "`Customization` provides domain separation; use an empty string for the\n"
        "IPsec/IKEv2 constructions in draft-ietf-ipsecme-sha3-02. `Length` is in\n"
        "bytes and is bound into the computation, so tags must not be truncated.",
        "Tag",
    )
    for arguments in (init, init + custom):
        add(
            "kmac_init",
            arguments,
            "kmac_state()",
            "Create an immutable keyed KMAC state for incremental messages.\n\n"
            + ("Customization defaults to the empty string. " if arguments == init else "Customization accepts iodata. ")
            + "The native state retains the algorithm\n"
            "and keyed sponge context. Keep it private like the key; updates return\n"
            "new states and finalization leaves the input state reusable.",
            "State",
        )
    add(
        "kmac_update",
        [("State", "kmac_state()"), ("Data", "iodata()")],
        "kmac_state()",
        "Absorb message iodata and return a new keyed KMAC state.\n\n"
        "The original state remains reusable. States from hash or XOF APIs are\n"
        "incompatible and raise an argument error.",
        "NewState",
    )
    add(
        "kmac_final",
        [("State", "kmac_state()"), ("Length", "non_neg_integer()")],
        "binary()",
        "Return a KMAC tag of exactly `Length` bytes without changing the state.\n\n"
        "Each call binds the requested length into the tag. To obtain a shorter\n"
        "tag, finalize again at that length; truncating a longer tag is incorrect.\n"
        "The state remains usable for additional updates or finalizations.",
        "Tag",
    )
    return tuple(sorted(result, key=lambda function: (function.name, function.arity)))


def functions(schema: NIFSchema) -> tuple[Function, ...]:
    result: list[Function] = []

    def add(name: str, arguments: list[tuple[str, str]], returns: str, doc: str, group: str, result_name: str = "Result") -> None:
        result.append(
            Function(name, tuple(Argument(*argument) for argument in arguments), returns, doc, group, result_name=result_name)
        )

    for group in PRIME_ORDER_GROUPS:
        name, byte_count, title = group.name, group.encoding_bytes, group.title
        point, scalar, table = f"{name}_point()", f"{name}_scalar()", f"{name}_precomputed()"
        operations = [
            (
                "identity",
                [],
                point,
                f"Return the {title} identity element, encoded as {byte_count} zero bytes.\n\n"
                "Adding this point leaves the other point unchanged. Multiplication by zero\n"
                "and multiplication of the identity by any scalar both return the identity.",
            ),
            (
                "base",
                [],
                point,
                f"Return the canonical {title} generator from RFC 9496.\n\n"
                "Use this point for interoperable generator multiplication.\n"
                "The base-scalar multiplication operation uses its built-in precomputed table.",
            ),
            (
                "point_is_valid",
                [("Point", "term()")],
                "boolean()",
                f"Return whether `Point` is a valid canonical {byte_count}-byte {title} encoding.\n\n"
                "The identity is valid. Wrong-sized binaries, noncanonical encodings, and\n"
                "non-binary terms return `false` instead of raising `badarg`.",
            ),
            (
                "point_eq",
                [("Left", point), ("Right", point)],
                "boolean()",
                "Return whether two encoded points represent the same group element.\n\n"
                "Both operands are decoded and validated. Invalid encodings raise `badarg`;\n"
                "`false` means that two valid points differ.",
            ),
            (
                "point_add",
                [("Left", point), ("Right", point)],
                point,
                "Return the canonical encoding of `Left + Right`.\n\n"
                "Both operands must be valid point encodings; otherwise raises `badarg`.\n"
                "Adding a point to its negation returns the identity.",
            ),
            (
                "point_sub",
                [("Left", point), ("Right", point)],
                point,
                "Return the canonical encoding of `Left - Right`.\n\n"
                "Both operands must be valid point encodings; otherwise raises `badarg`.\n"
                "Subtracting a point from itself returns the identity.",
            ),
            (
                "point_negate",
                [("Point", point)],
                point,
                "Return the additive inverse of `Point` in canonical encoding.\n\n"
                "The input point and its negation add to the identity.\n"
                "An invalid point encoding raises `badarg`.",
            ),
            (
                "point_double",
                [("Point", point)],
                point,
                "Return `Point + Point` in canonical encoding.\n\n"
                "This is equivalent to multiplication by the scalar two.\n"
                "An invalid point encoding raises `badarg`.",
            ),
            (
                "point_scalarmul",
                [("Point", point), ("Scalar", scalar)],
                point,
                "Return `Scalar * Point` in canonical encoding.\n\n"
                "The point must be valid and the scalar must already be canonical.\n"
                "Invalid operands raise `badarg`; zero and the identity are accepted.",
            ),
            (
                "base_scalarmul",
                [("Scalar", scalar)],
                point,
                f"Multiply the canonical {title} generator by `Scalar`.\n\n"
                "Uses the native library's built-in precomputed generator table.\n"
                "The scalar must already be canonical; otherwise raises `badarg`.",
            ),
            (
                "point_double_scalarmul",
                [("Point1", point), ("Scalar1", scalar), ("Point2", point), ("Scalar2", scalar)],
                point,
                "Return `Scalar1 * Point1 + Scalar2 * Point2` in canonical encoding.\n\n"
                "Computes the same result as two scalar multiplications followed by addition.\n"
                "Both points must be valid and both scalars canonical; otherwise raises `badarg`.",
            ),
            (
                "point_from_hash",
                [("UniformBytes", "binary()")],
                point,
                f"Derive a {title} element from exactly {2 * byte_count} bytes using RFC 9496.\n\n"
                "The two halves are mapped separately and their points are added. Uniform\n"
                "input gives an approximately uniform group element. This operation does\n"
                "not hash a message: use a protocol-defined, domain-separated hash or XOF\n"
                "to prepare the input. Wrong-sized binaries and non-binaries raise `badarg`.",
            ),
            (
                "point_from_hash_nonuniform",
                [("Bytes", "binary()")],
                point,
                f"Apply the upstream single map to exactly {byte_count} bytes.\n\n"
                "This is one half of the two-map RFC 9496 derivation. Its output has a\n"
                "different distribution, so use it only when a protocol requires the single\n"
                "map. Wrong-sized binaries and non-binaries raise `badarg`.",
            ),
            (
                "precompute",
                [("Point", point)],
                table,
                "Build an immutable native multiplication table for `Point`.\n\n"
                "Reuse the table when multiplying the same point by many scalars.\n"
                "The resource can be shared between processes and is released automatically\n"
                f"when no references remain. It is specific to {title}; invalid points raise `badarg`.",
            ),
            (
                "precomputed_scalarmul",
                [("Precomputed", table), ("Scalar", scalar)],
                point,
                "Multiply the point stored in `Precomputed` by `Scalar`.\n\n"
                "The result matches ordinary point-scalar multiplication; the table is unchanged.\n"
                f"A resource from another group, a non-table term, or a noncanonical {title}\n"
                "scalar raises `badarg`.",
            ),
            (
                "scalar_is_canonical",
                [("Scalar", "term()")],
                "boolean()",
                f"Return whether `Scalar` is a canonical {byte_count}-byte little-endian scalar.\n\n"
                "Its integer value must be smaller than the group order; zero is accepted.\n"
                "Wrong-sized binaries, out-of-range values, and non-binaries return `false`.",
            ),
            (
                "scalar_reduce",
                [("Bytes", "binary()")],
                scalar,
                "Reduce an arbitrary-length unsigned little-endian integer modulo the group order.\n\n"
                f"Returns a canonical {byte_count}-byte scalar. Leading zero bytes at the\n"
                "most-significant end are allowed, and the empty binary reduces to zero.\n"
                "This operation does not hash or clamp its input. Non-binaries raise `badarg`.",
            ),
            (
                "scalar_add",
                [("Left", scalar), ("Right", scalar)],
                scalar,
                "Return `(Left + Right) mod l`, where `l` is the group order.\n\n"
                "Both operands must already be canonical scalars; otherwise raises `badarg`.\n"
                "The result is canonically encoded.",
            ),
            (
                "scalar_sub",
                [("Left", scalar), ("Right", scalar)],
                scalar,
                "Return `(Left - Right) mod l`, where `l` is the group order.\n\n"
                "Both operands must already be canonical scalars; otherwise raises `badarg`.\n"
                "A negative difference wraps modulo `l` and the result is canonically encoded.",
            ),
            (
                "scalar_mul",
                [("Left", scalar), ("Right", scalar)],
                scalar,
                "Return `(Left * Right) mod l`, where `l` is the group order.\n\n"
                "Both operands must already be canonical scalars; otherwise raises `badarg`.\n"
                "The result is canonically encoded.",
            ),
            (
                "scalar_negate",
                [("Scalar", scalar)],
                scalar,
                "Return `-Scalar mod l`, where `l` is the group order.\n\n"
                "The result adds to the input to give zero; zero is its own negation.\n"
                "A noncanonical scalar raises `badarg`.",
            ),
            (
                "scalar_halve",
                [("Scalar", scalar)],
                scalar,
                "Divide `Scalar` by two modulo the group order.\n\n"
                "This is multiplication by the modular inverse of two, rather than integer\n"
                "division. Adding the result to itself recovers the input, including for odd\n"
                "scalars. A noncanonical scalar raises `badarg`.",
            ),
            (
                "scalar_invert",
                [("Scalar", scalar)],
                f"{scalar} | error",
                "Return the multiplicative inverse of `Scalar` modulo the group order.\n\n"
                "Multiplying a nonzero scalar by its inverse gives the canonical scalar one.\n"
                "Zero has no inverse and returns `error`. Noncanonical scalars raise `badarg`.",
            ),
        ]
        for operation, arguments, returns, doc in operations:
            add(f"{name}_{operation}", arguments, returns, doc, title)

    for curve, title in [("ed25519", "Ed25519"), ("ed448", "Ed448")]:
        secret, public, signature, keypair = (f"{curve}_{part}()" for part in ["secret_key", "public_key", "signature", "keypair"])
        context = "ed25519_context()" if curve == "ed25519" else "binary()"
        args_keypair = [("Keypair", keypair), ("Message", "binary()")]
        args_keys = [("SecretKey", secret), ("PublicKey", public), ("Message", "binary()")]
        args_verify = [("Signature", signature), ("PublicKey", public), ("Message", "binary()")]
        flags = [("Prehashed", "prehashed()"), ("Context", context)]
        context_arg = [("Context", context)]
        context_doc = (
            "Use `no_context` for pure Ed25519, or a binary of at most 255 bytes for Ed25519ctx/Ed25519ph."
            if curve == "ed25519"
            else "Context is a binary of at most 255 bytes; use `<<>>` for an empty context."
        )
        flag_doc = "`Prehashed` is `0` for a message or `1` for an already computed 64-byte prehash."
        operations = [
            (
                "derive_keypair",
                [("SecretKey", secret)],
                keypair,
                f"Derive an immutable {title} keypair resource from a secret seed.",
            ),
            ("derive_public_key", [("SecretKey", secret)], public, f"Derive a {title} public key from a secret seed."),
            (
                "keypair_extract_private_key",
                [("Keypair", keypair)],
                secret,
                "Extract the secret seed from a keypair resource.\nKeep the returned bytes private.",
            ),
            ("keypair_extract_public_key", [("Keypair", keypair)], public, "Extract the public key from a keypair resource."),
            ("keypair_sign", args_keypair + flags, signature, f"Sign with a {title} keypair resource.\n{flag_doc}\n{context_doc}"),
            (
                "keypair_sign_prehash",
                args_keypair + context_arg,
                signature,
                f"Prehash the message internally and sign using {title}ph.\n{context_doc}",
            ),
            (
                "sign",
                args_keys + flags,
                signature,
                f"Sign using a {title} secret seed and matching public key.\nMismatched keys raise an error.\n{flag_doc}\n{context_doc}",
            ),
            (
                "sign_prehash",
                args_keys + context_arg,
                signature,
                f"Prehash the message internally and sign using {title}ph.\nThe secret seed and public key must match.\n{context_doc}",
            ),
            (
                "verify",
                args_verify + flags,
                "boolean()",
                f"Verify a {title} signature, returning `false` when verification fails.\n{flag_doc}\n{context_doc}",
            ),
            (
                "verify_prehash",
                args_verify + context_arg,
                "boolean()",
                f"Prehash the message internally and verify a {title}ph signature.\n{context_doc}",
            ),
        ]
        for operation, arguments, returns, doc in operations:
            add(f"{curve}_{operation}", arguments, returns, doc, title)
        xcurve = "x25519" if curve == "ed25519" else "x448"
        add(
            f"{curve}_convert_public_key_to_{xcurve}",
            [("PublicKey", public)],
            f"{xcurve}_public_key()",
            f"Convert an encoded {title} public key to its {xcurve.upper()} public-key encoding.",
            title,
        )
        add(
            f"{curve}_convert_private_key_to_{xcurve}",
            [("SecretKey", secret)],
            f"{xcurve}_scalar()",
            f"Derive an {xcurve.upper()} scalar from a {title} secret seed.",
            title,
        )

    for curve in ["x25519", "x448"]:
        add(
            f"{curve}_derive_public_key",
            [("Scalar", f"{curve}_scalar()")],
            f"{curve}_public_key()",
            f"Derive an {curve.upper()} public key from a secret scalar.",
            "Diffie-Hellman",
        )
        add(
            curve,
            [("PublicKey", f"{curve}_public_key()"), ("Scalar", f"{curve}_scalar()")],
            f"{curve}_shared_secret() | error",
            "Compute a Diffie-Hellman shared secret.\nThe public key comes first and the secret scalar second.\nReturn `error` when the upstream operation rejects the input, including low-order points.",
            "Diffie-Hellman",
        )

    hash_operations = [
        (
            "hash",
            [("Type", "hash_algorithm()"), ("Data", "iodata()")],
            "binary()",
            "Hash iodata using the configured default digest length.",
        ),
        (
            "hash",
            [("Type", "hash_algorithm()"), ("Data", "iodata()"), ("Length", "non_neg_integer()")],
            "binary()",
            "Hash iodata and return Length bytes. The length must not exceed the configured maximum for the algorithm.",
        ),
        (
            "hash_init",
            [("Type", "hash_algorithm()")],
            "hash_state()",
            "Create an immutable native hash state. The resource retains the algorithm and its default digest length.",
        ),
        (
            "hash_update",
            [("State", "hash_state()"), ("Data", "iodata()")],
            "hash_state()",
            "Absorb iodata and return a new native hash state. The original state remains reusable.",
        ),
        (
            "hash_final",
            [("State", "hash_state()")],
            "binary()",
            "Return the digest using the state's configured default length. The input state remains reusable.",
        ),
        (
            "hash_final",
            [("State", "hash_state()"), ("Length", "non_neg_integer()")],
            "binary()",
            "Return Length digest bytes without changing the input state. The length must not exceed the configured maximum.",
        ),
    ]
    for name, arguments, returns, doc in hash_operations:
        result_name = {"hash_init": "State", "hash_update": "NewState"}.get(name, "Digest")
        add(name, arguments, returns, doc, "Hash API", result_name=result_name)
    result.extend(xof_functions(schema))
    result.extend(kmac_functions(schema))

    rng = [
        (
            "init_from_buffer",
            [("Seed", "iodata()"), ("Deterministic", "boolean()")],
            "spongerng_state()",
            "Initialize a sponge PRNG from seed bytes.\n`Deterministic` selects the upstream PRNG's deterministic mode.",
        ),
        (
            "init_from_file",
            [("Filename", "iodata()"), ("InputLen", "non_neg_integer()"), ("Deterministic", "boolean()")],
            "spongerng_state()",
            "Initialize a sponge PRNG by reading `InputLen` bytes from a file.\n`Filename` contains nonempty native filename bytes; file errors raise an exception.",
        ),
        (
            "init_from_dev_urandom",
            [],
            "spongerng_state()",
            "Initialize a sponge PRNG using `/dev/urandom`.\nRaise an exception if the entropy source cannot be read.",
        ),
        (
            "next",
            [("State", "spongerng_state()"), ("OutputLen", "non_neg_integer()")],
            "{spongerng_state(), binary()}",
            "Generate bytes and return the new PRNG state together with those bytes.\nContinue with the returned state to advance the stream.",
        ),
        (
            "stir",
            [("State", "spongerng_state()"), ("Input", "iodata()")],
            "spongerng_state()",
            "Mix additional seed bytes into a PRNG state and return a new state.",
        ),
    ]
    for operation, arguments, returns, doc in rng:
        add(f"spongerng_csprng_{operation}", arguments, returns, doc, "Sponge PRNG")
    identifiers = [(function.name, function.arity) for function in result]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Generated Erlang function names and arities must be unique")
    return tuple(sorted(result, key=lambda function: (function.name, function.arity)))


def types(schema: NIFSchema) -> tuple[tuple[str, str, str], ...]:
    result = [
        ("hash_algorithm", " | ".join(sorted(schema.hash)) or "none()", "Configured fixed-output hash algorithms."),
        ("prehashed", "0 | 1", "Select an ordinary message (`0`) or an already computed 64-byte prehash (`1`)."),
        (
            "ed25519_context",
            "no_context | binary()",
            "Use `no_context` for pure Ed25519, or a context binary of at most 255 bytes.",
        ),
        (
            "hash_state",
            "erlang:nif_resource()",
            "Any configured immutable hash state.",
        ),
        ("spongerng_state", "erlang:nif_resource()", "A sponge PRNG resource. Continue with each operation's returned state."),
    ]
    if schema.kmac:
        result.extend(
            [
                ("kmac_algorithm", " | ".join(sorted(schema.kmac)), "SP 800-185 KMAC variants accepted by the KMAC API."),
                ("kmac_state", "erlang:nif_resource()", "An immutable keyed KMAC resource. Keep this state private like its key."),
            ]
        )
    for group in xof_groups(schema):
        result.append((group.algorithm_type, " | ".join(group.algorithms), f"Algorithms accepted by `{group.name}/3`."))
        result.append(
            (
                group.state_type,
                "erlang:nif_resource()",
                f"An opaque native `{group.name}` state. States from other groups are incompatible.",
            )
        )
    for curve, size in [("ed25519", 32), ("ed448", 57)]:
        for part, byte_count in [("secret_key", size), ("public_key", size), ("signature", size * 2)]:
            result.append(
                (
                    f"{curve}_{part}",
                    f"<<_:{byte_count * 8}>>",
                    f"A {byte_count}-byte {curve.upper()} {part.replace('_', ' ')} encoding.",
                )
            )
        result.append((f"{curve}_keypair", "erlang:nif_resource()", f"An immutable native {curve.upper()} keypair resource."))
    for curve, size in [("x25519", 32), ("x448", 56)]:
        for part in ["scalar", "public_key", "shared_secret"]:
            result.append(
                (f"{curve}_{part}", f"<<_:{size * 8}>>", f"A {size}-byte {curve.upper()} {part.replace('_', ' ')} encoding.")
            )
    for profile in PRIME_ORDER_GROUPS:
        group, size = profile.name, profile.encoding_bytes
        for part in ["point", "scalar"]:
            result.append((f"{group}_{part}", f"<<_:{size * 8}>>", f"A canonical {size}-byte {group} {part} encoding."))
        result.append((f"{group}_precomputed", "erlang:nif_resource()", f"An immutable native multiplication table for {group}."))
    return tuple(sorted(result, key=lambda item: item[0]))
