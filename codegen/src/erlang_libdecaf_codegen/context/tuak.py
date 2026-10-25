"""TUAK's fixed-size inputs, per-operation options, and native/public contracts."""

from dataclasses import dataclass, replace
import re

from .functions import Argument, Function


@dataclass(frozen=True)
class Input:
    name: str
    type: str
    c_name: str
    lengths: tuple[int, ...]


@dataclass(frozen=True)
class Option:
    name: str
    lengths: tuple[int, ...]


OPTIONS = (
    Option("mac_length", (8, 16, 32)),
    Option("res_length", (4, 8, 16, 32)),
    Option("ck_length", (16, 32)),
    Option("ik_length", (16, 32)),
    Option("iterations", ()),
)


@dataclass(frozen=True)
class Operation:
    name: str
    inputs: tuple[Input, ...]
    options: tuple[str, ...]
    result_name: str
    returns: str
    doc: str
    member: str | None = None

    @property
    def arity(self):
        return len(self.inputs)

    @property
    def options_type(self):
        if self.name in ("f1", "f1_star"):
            return "mac_options"
        if self.name in ("f2", "f3", "f4", "f5", "f2345"):
            return "derive_options"
        return "options"


KEY = Input("Key", "key", "key", (16, 32))
TOP = Input("TOP", "top", "top", (32,))
TOPC = Input("TOPc", "topc", "topc", (32,))
RAND = Input("RAND", "rand", "rand", (16,))
SQN = Input("SQN", "sqn", "sqn", (6,))
AMF = Input("AMF", "amf", "amf", (2,))


def operations():
    derived = ("res_length", "ck_length", "ik_length", "iterations")
    result = [
        Operation(
            "topc",
            (KEY, TOP),
            ("iterations",),
            "TOPc",
            "topc()",
            "Derive the subscriber-specific TOPc from the subscriber key and the operator's TOP.\n"
            "Reuse TOPc with the same key and iteration count for subsequent TUAK operations.",
        ),
        Operation(
            "f1",
            (KEY, TOPC, RAND, SQN, AMF),
            ("mac_length", "iterations"),
            "MAC_A",
            "mac()",
            "Compute the network authentication code MAC-A over RAND, SQN, and AMF.",
        ),
        Operation(
            "f1_star",
            (KEY, TOPC, RAND, SQN, AMF),
            ("mac_length", "iterations"),
            "MAC_S",
            "mac()",
            "Compute the resynchronization authentication code MAC-S.\n"
            "Pass the mobile station's sequence number as SQN and the protocol's resynchronization AMF.",
        ),
        Operation(
            "f2345",
            (KEY, TOPC, RAND),
            derived,
            "Outputs",
            "{res(), ck(), ik(), ak()}",
            "Compute the response RES, confidentiality key CK, integrity key IK, and anonymity key AK\n"
            "together in one TUAK evaluation. Return {RES, CK, IK, AK}.",
        ),
        Operation(
            "f5_star",
            (KEY, TOPC, RAND),
            ("iterations",),
            "AK_Star",
            "ak()",
            "Compute the six-byte resynchronization anonymity key AK* for RAND.",
        ),
    ]
    for name, member, title in [
        ("f2", "res", "authentication response RES"),
        ("f3", "ck", "confidentiality key CK"),
        ("f4", "ik", "integrity key IK"),
        ("f5", "ak", "six-byte anonymity key AK"),
    ]:
        result.append(
            Operation(
                name,
                (KEY, TOPC, RAND),
                derived,
                member.upper(),
                f"{member}()",
                f"Compute the {title} for RAND.\n"
                "All three output-length choices affect the shared f2/f3/f4/f5 computation,\n"
                "so use the same options for each function. Use f2345 to obtain all four outputs together.",
                member=member,
            )
        )
    return tuple(sorted(result, key=lambda op: op.name))


def functions():
    result = []
    for op in operations():
        args = tuple(Argument(i.name, f"tuak_{i.type}()") for i in op.inputs)
        for with_options in (False, True):
            arguments = args + ((Argument("Options", f"tuak_{op.options_type}()"),) if with_options else ())
            returns = re.sub(r"\b([a-z_]+)\(\)", r"tuak_\1()", op.returns)
            result.append(
                Function(
                    f"tuak_{op.name}",
                    arguments,
                    returns,
                    f"TUAK {op.name}: {op.doc.splitlines()[0]}",
                    "TUAK API",
                    "tuak",
                    op.name,
                    result_name=op.result_name,
                )
            )
    return tuple(result)


def public_functions():
    return tuple(
        replace(
            f,
            name=f.name.removeprefix("tuak_"),
            arguments=tuple(Argument(a.name, a.type.replace("tuak_", "")) for a in f.arguments),
            returns=f.returns.replace("tuak_", ""),
        )
        for f in functions()
    )


def types(schema):
    result = [
        ("key", "<<_:128>> | <<_:256>>", "A 16- or 32-byte subscriber key K."),
        ("top", "<<_:256>>", "The 32-byte operator configuration TOP."),
        ("topc", "<<_:256>>", "The 32-byte subscriber-specific TOPc derived from TOP and K."),
        ("rand", "<<_:128>>", "The 16-byte authentication challenge RAND."),
        ("sqn", "<<_:48>>", "The six-byte sequence number SQN (SQN_MS during resynchronization)."),
        ("amf", "<<_:16>>", "The two-byte authentication management field AMF."),
        ("mac", "<<_:64>> | <<_:128>> | <<_:256>>", "An 8-, 16-, or 32-byte authentication code, MAC-A or MAC-S."),
        ("res", "<<_:32>> | <<_:64>> | <<_:128>> | <<_:256>>", "A 4-, 8-, 16-, or 32-byte authentication response RES."),
        ("ck", "<<_:128>> | <<_:256>>", "A 16- or 32-byte confidentiality key CK."),
        ("ik", "<<_:128>> | <<_:256>>", "A 16- or 32-byte integrity key IK."),
        ("ak", "<<_:48>>", "A six-byte anonymity key, AK or AK*."),
        (
            "iterations",
            "1..4294967295",
            "Number of complete 24-round Keccak-f[1600] permutations; default "
            f"{schema.default_iterations}. Use the same count for TOPc derivation and its subsequent operations. "
            "Long evaluations yield between bounded batches and stop when their caller is terminated.",
        ),
    ]
    for option in OPTIONS:
        if option.lengths:
            default = getattr(schema, "default_" + option.name)
            result.append(
                (
                    option.name,
                    " | ".join(map(str, option.lengths)),
                    f"Supported {option.name.replace('_', ' ')} values in bytes; default {default}.",
                )
            )
    for name, opts in [
        ("options", ("iterations",)),
        ("mac_options", ("mac_length", "iterations")),
        ("derive_options", ("res_length", "ck_length", "ik_length", "iterations")),
    ]:
        definition = "#{" + ", ".join(f"{opt} => tuak_{opt}()" for opt in opts) + "}"
        result.append(
            (
                name,
                definition,
                "Optional settings for this TUAK operation. Unspecified settings use the configured defaults;\n"
                "unknown or inapplicable keys raise badarg. Lengths participate in domain separation.",
            )
        )
    return tuple(sorted((f"tuak_{name}", definition, doc) for name, definition, doc in result))
