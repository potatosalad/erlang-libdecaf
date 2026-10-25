"""Compatibility contracts for the historical top-level libdecaf API."""

from dataclasses import dataclass
import re

from ..schema import NIF as NIFSchema
from .functions import Argument, Function, functions, types


@dataclass(frozen=True)
class DeprecatedFunction(Function):
    implementation: str = ""
    replacement: str = ""


def deprecated_functions(schema: NIFSchema) -> tuple[DeprecatedFunction, ...]:
    native = {(f.name, f.arity): f for f in functions(schema)}
    native_types = {name for name, _, _ in types(schema)}
    result = []

    def qualify(definition):
        return re.sub(
            r"(?<![:\w])([a-z][a-z0-9_]*)\(\)",
            lambda match: ("libdecaf_nif:" if match[1] in native_types else "") + match[0],
            definition,
        )

    def add(name, arguments, returns, doc, implementation, replacement):
        result.append(
            DeprecatedFunction(
                name,
                tuple(Argument(arg, qualify(kind)) for arg, kind in arguments),
                qualify(returns),
                doc,
                "Deprecated API",
                implementation=implementation,
                replacement=replacement,
            )
        )

    def forward(function, name=None):
        arguments = [(a.name, a.type) for a in function.arguments]
        parameters = ", ".join(a.name for a in function.arguments)
        add(
            name or function.name,
            arguments,
            function.returns,
            function.doc,
            f"libdecaf_nif:{function.name}({parameters})",
            f"Use libdecaf_nif:{function.name}/{function.arity} instead.",
        )

    # Keep the historical low-level argument order, keypair resources, and flags.
    for function in native.values():
        if function.name.startswith(("ed25519_", "ed448_")) or function.name in (
            "x25519",
            "x448",
            "x25519_derive_public_key",
            "x448_derive_public_key",
        ):
            forward(function)
    for curve in ("x25519", "x448"):
        forward(native[(f"{curve}_derive_public_key", 1)], f"{curve}_generate_key")

    for algorithm, profile in sorted(schema.hash.items()):
        if not algorithm.startswith(("sha2_", "sha3_", "keccak_")):
            continue
        size = profile.default_output_len
        for arity in (1, 2):
            function = native[(algorithm, arity)]
            parameters = ", ".join(a.name for a in function.arguments)
            add(
                algorithm,
                [(a.name, a.type) for a in function.arguments],
                function.returns,
                f"Hash iodata using {algorithm}; the default digest length is {size} bytes.\n"
                f"An explicit output length may truncate the digest to 0 through {size} bytes.",
                f"libdecaf_nif:{algorithm}({parameters})",
                (
                    f"Use libdecaf:hash({algorithm}, Input) instead."
                    if arity == 1
                    else f"Use libdecaf:hash({{{algorithm}, OutputLength}}, Input) instead."
                ),
            )
        add(
            f"{algorithm}_init",
            [],
            "hash_state()",
            f"Initialize an immutable {algorithm} hash state with its full {size}-byte digest length.\n"
            "Return the native state directly, without an algorithm tuple.",
            f"libdecaf_nif:hash_init({algorithm})",
            f"Use libdecaf:hash_init({algorithm}) instead.",
        )
        add(
            f"{algorithm}_update",
            [("State", "hash_state()"), ("Input", "iodata()")],
            "hash_state()",
            f"Absorb iodata into an {algorithm} state and return a new native state.\nThe input state remains reusable.",
            "libdecaf_nif:hash_update(State, Input)",
            "Use libdecaf:hash_update/2 instead.",
        )
        add(
            f"{algorithm}_final",
            [("State", "hash_state()")],
            "binary()",
            f"Return the full {size}-byte {algorithm} digest without changing the native state.",
            "libdecaf_nif:hash_final(State)",
            "Use libdecaf:hash_final/1 instead.",
        )
        add(
            f"{algorithm}_final",
            [("State", "hash_state()"), ("OutputLength", "non_neg_integer()")],
            "binary()",
            f"Return an {algorithm} digest prefix without changing the native state.\n"
            f"OutputLength is in bytes and must be between 0 and {size}.",
            "binary:part(libdecaf_nif:hash_final(State), 0, OutputLength)",
            f"Use libdecaf:hash_init({{{algorithm}, OutputLength}}) and libdecaf:hash_final/1 instead.",
        )

    for algorithm in ("shake128", "shake256"):
        add(
            algorithm,
            [("Input", "iodata()"), ("OutputLength", "non_neg_integer()")],
            "binary()",
            f"Return OutputLength bytes of {algorithm} output from iodata.",
            f"libdecaf_nif:{algorithm}(Input, OutputLength)",
            f"Use libdecaf:xof({algorithm}, Input, OutputLength) instead.",
        )
        add(
            f"{algorithm}_init",
            [],
            "xof_state()",
            f"Initialize an immutable absorbing {algorithm} native state.",
            f"libdecaf_nif:xof_init({algorithm})",
            f"Use libdecaf:xof_init({algorithm}) instead.",
        )
        add(
            f"{algorithm}_update",
            [("State", "xof_state()"), ("Input", "iodata()")],
            "xof_state()",
            f"Absorb iodata into {algorithm} and return a new native state.\nThe input state remains reusable.",
            "libdecaf_nif:xof_absorb(State, Input)",
            "Use libdecaf:xof_absorb/2 instead.",
        )
        add(
            f"{algorithm}_final",
            [("State", "xof_state()"), ("OutputLength", "non_neg_integer()")],
            "binary()",
            f"Return OutputLength bytes from an absorbing {algorithm} state.\n"
            "Return only the output binary; finalizing the same immutable state repeats the output.",
            "element(2, libdecaf_nif:xof_squeeze(State, OutputLength))",
            "Use libdecaf:xof_squeeze/2, which returns {NextState, Output}, instead.",
        )

    for function in native.values():
        if function.name.startswith("spongerng_csprng_"):
            forward(function, function.name.replace("_csprng_", "_", 1))

    add(
        "priv_dir",
        [],
        "file:filename_all()",
        "Locate libdecaf's priv directory, including the historical fallback when the application is not loaded.",
        """case code:priv_dir(?MODULE) of
    {error, bad_name} ->
        case code:which(?MODULE) of
            Filename when is_list(Filename) ->
                filename:join([filename:dirname(Filename), "../priv"]);
            _ ->
                "../priv"
        end;
    Directory ->
        Directory
end""",
        "Use code:priv_dir(libdecaf) for a loaded application instead.",
    )
    return tuple(sorted(result, key=lambda function: (function.name, function.arity)))
