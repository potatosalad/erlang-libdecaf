"""Documentation and type contracts for libdecaf's Erlang NIF interface."""

from dataclasses import dataclass

from ..schema import NIF as NIFSchema


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

    @property
    def arity(self) -> int:
        return len(self.arguments)

    @property
    def parameters(self) -> str:
        return ", ".join("_" + argument.name for argument in self.arguments)

    @property
    def spec(self) -> str:
        arguments = ", ".join(f"{argument.name} :: {argument.type}" for argument in self.arguments)
        return f"{self.name}({arguments}) -> {self.returns}"

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


def functions(schema: NIFSchema) -> tuple[Function, ...]:
    result: list[Function] = []

    def add(name: str, arguments: list[tuple[str, str]], returns: str, doc: str, group: str) -> None:
        result.append(Function(name, tuple(Argument(*argument) for argument in arguments), returns, doc, group))

    for name, byte_count, title in [("ristretto255", 32, "Ristretto255"), ("decaf448", 56, "Decaf448")]:
        point, scalar, table = f"{name}_point()", f"{name}_scalar()", f"{name}_precomputed()"
        operations = [
            ("identity", [], point, f"Return the {title} identity element in its canonical {byte_count}-byte encoding."),
            ("base", [], point, f"Return the canonical {title} generator encoding."),
            (
                "point_is_valid",
                [("Point", "term()")],
                "boolean()",
                "Check whether a term is a canonical point encoding, including the identity.",
            ),
            ("point_eq", [("Left", point), ("Right", point)], "boolean()", "Compare two canonical group elements."),
            ("point_add", [("Left", point), ("Right", point)], point, "Add two group elements."),
            ("point_sub", [("Left", point), ("Right", point)], point, "Subtract the right group element from the left."),
            ("point_negate", [("Point", point)], point, "Return the additive inverse of a group element."),
            ("point_double", [("Point", point)], point, "Double a group element."),
            ("point_scalarmul", [("Point", point), ("Scalar", scalar)], point, "Multiply a group element by a canonical scalar."),
            ("base_scalarmul", [("Scalar", scalar)], point, "Multiply the group generator by a canonical scalar."),
            (
                "point_double_scalarmul",
                [("Point1", point), ("Scalar1", scalar), ("Point2", point), ("Scalar2", scalar)],
                point,
                "Compute `Scalar1 * Point1 + Scalar2 * Point2`.",
            ),
            (
                "point_from_hash",
                [("UniformBytes", "binary()")],
                point,
                f"Map {2 * byte_count} uniformly distributed bytes to a group element using RFC 9496 element derivation.\nExpand or hash messages to the required uniform input before calling this function.",
            ),
            (
                "point_from_hash_nonuniform",
                [("Bytes", "binary()")],
                point,
                f"Apply the upstream single map to {byte_count} bytes.\nIts output distribution differs from the uniform RFC 9496 derivation.",
            ),
            (
                "precompute",
                [("Point", point)],
                table,
                "Create an immutable multiplication table for a group element.\nThe returned resource can be shared between processes.",
            ),
            (
                "precomputed_scalarmul",
                [("Precomputed", table), ("Scalar", scalar)],
                point,
                "Multiply the precomputed group element by a canonical scalar.",
            ),
            (
                "scalar_is_canonical",
                [("Scalar", "term()")],
                "boolean()",
                "Check whether a term is a canonical scalar encoding, including zero.",
            ),
            (
                "scalar_reduce",
                [("Bytes", "binary()")],
                scalar,
                "Reduce an arbitrary-length little-endian integer modulo the group order.",
            ),
            ("scalar_add", [("Left", scalar), ("Right", scalar)], scalar, "Add two canonical scalars modulo the group order."),
            (
                "scalar_sub",
                [("Left", scalar), ("Right", scalar)],
                scalar,
                "Subtract the right scalar from the left modulo the group order.",
            ),
            ("scalar_mul", [("Left", scalar), ("Right", scalar)], scalar, "Multiply two canonical scalars modulo the group order."),
            ("scalar_negate", [("Scalar", scalar)], scalar, "Negate a canonical scalar modulo the group order."),
            ("scalar_halve", [("Scalar", scalar)], scalar, "Divide a canonical scalar by two modulo the group order."),
            (
                "scalar_invert",
                [("Scalar", scalar)],
                f"{scalar} | error",
                "Invert a scalar modulo the group order, returning `error` for zero.",
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
            [("Type", "hash_algorithm()"), ("Input", "iodata()")],
            "binary()",
            "Hash iodata using the configured default digest length.",
        ),
        (
            "hash",
            [("Type", "hash_algorithm()"), ("Input", "iodata()"), ("Length", "non_neg_integer()")],
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
            [("State", "hash_state()"), ("Input", "iodata()")],
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
        add(name, arguments, returns, doc, "Hash API")
    result.extend(xof_functions(schema))

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
    for group, size in [("ristretto255", 32), ("decaf448", 56)]:
        for part in ["point", "scalar"]:
            result.append((f"{group}_{part}", f"<<_:{size * 8}>>", f"A canonical {size}-byte {group} {part} encoding."))
        result.append((f"{group}_precomputed", "erlang:nif_resource()", f"An immutable native multiplication table for {group}."))
    return tuple(sorted(result, key=lambda item: item[0]))
