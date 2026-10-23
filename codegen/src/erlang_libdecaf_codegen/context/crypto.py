"""Hash/XOF contracts shared by the C and Erlang generators."""

from dataclasses import dataclass
from .functions import Argument, Function


@dataclass(frozen=True)
class Family:
    name: str
    hash_algorithms: tuple[str, ...]
    xof_algorithms: tuple[str, ...]
    hash_forms: tuple[tuple[str, ...], ...]
    xof_forms: tuple[tuple[str, ...], ...]

    @property
    def prefix(self):
        return "libdecaf_nif_" + self.name

    @property
    def directory(self):
        return {"sha2": "hash", "kmac": "kmac", "tuplehash": "tuplehash", "parallelhash": "parallelhash"}.get(self.name, "xof")

    @property
    def basename(self):
        return "hash_sha2" if self.name == "sha2" else "xof_" + self.name if self.directory == "xof" else self.name

    @property
    def header(self):
        return self.directory + "/" + self.basename + ".h"

    def functions(self, mode):
        return tuple(f for f in api_functions_for_family(self) if f.family == mode)


TYPES = {
    "OutputLength": "non_neg_integer()",
    "FunctionName": "iodata()",
    "CustomizationString": "iodata()",
    "Key": "iodata()",
    "BlockSize": "pos_integer()",
    "DomainSeparation": "1..127",
}


def families(schema):
    fixed = lambda prefix: tuple(sorted(n for n in schema.hash if n.startswith(prefix)))
    xof = lambda group: tuple(sorted(n for n, p in schema.xof.items() if p.group == group))
    return (
        Family(
            "hopmac",
            tuple(sorted(schema.hopmac)),
            xof("hopmac"),
            (("OutputLength", "Key"), ("OutputLength", "Key", "CustomizationString")),
            (("Key",), ("Key", "CustomizationString")),
        ),
        Family(
            "cshake",
            xof("cshake"),
            xof("cshake"),
            (("OutputLength",), ("OutputLength", "FunctionName", "CustomizationString")),
            ((), ("FunctionName", "CustomizationString")),
        ),
        Family("keccak", fixed("keccak") + xof("keccak"), xof("keccak"), ((), ("OutputLength",)), ((),)),
        Family(
            "kmac",
            tuple(sorted(schema.kmac)),
            xof("kmac"),
            (("OutputLength", "Key"), ("OutputLength", "Key", "CustomizationString")),
            (("Key",), ("Key", "CustomizationString")),
        ),
        Family(
            "kt",
            xof("kt"),
            xof("kt"),
            ((), ("OutputLength",), ("OutputLength", "CustomizationString")),
            ((), ("CustomizationString",)),
        ),
        Family(
            "parallelhash",
            tuple(sorted(schema.parallelhash)),
            xof("parallelhash"),
            (("OutputLength", "BlockSize"), ("OutputLength", "BlockSize", "CustomizationString")),
            (("BlockSize",), ("BlockSize", "CustomizationString")),
        ),
        Family("sha2", fixed("sha2"), (), ((), ("OutputLength",)), ()),
        Family("sha3", fixed("sha3") + xof("sha3"), xof("sha3"), ((), ("OutputLength",)), ((),)),
        Family(
            "tuplehash",
            tuple(sorted(schema.tuplehash)),
            xof("tuplehash"),
            (("OutputLength",), ("OutputLength", "CustomizationString")),
            ((), ("CustomizationString",)),
        ),
        Family(
            "turboshake",
            xof("turboshake"),
            xof("turboshake"),
            ((), ("OutputLength",), ("OutputLength", "DomainSeparation")),
            ((), ("DomainSeparation",)),
        ),
    )


def api_functions_for_family(family):
    result = []
    for mode, forms, algorithms in (
        ("hash", family.hash_forms, family.hash_algorithms),
        ("xof", family.xof_forms, family.xof_algorithms),
    ):
        for form in forms:
            accepted = algorithms
            if mode == "hash" and not form and family.name in ("sha3", "keccak"):
                accepted = tuple(n for n in algorithms if n.startswith("sha3_") or n.startswith("keccak_"))
            algtype = " | ".join(accepted) or "none()"
            initargs = (("Type", algtype),) + tuple((p, TYPES[p]) for p in form)
            onceform = form if mode == "hash" else ("OutputLength",) + form
            onceargs = (("Type", algtype), ("Input", "[iodata()]" if family.name == "tuplehash" else "iodata()")) + tuple(
                (p, TYPES[p]) for p in onceform
            )
            for name, args, returns, operation in (
                (f"{mode}_init_{family.name}", initargs, f"{mode}_state()", "init"),
                (f"{mode}_{family.name}", onceargs, "binary()", "once"),
            ):
                result.append(
                    Function(
                        name,
                        tuple(Argument(*a) for a in args),
                        returns,
                        f"{'Initialize' if operation == 'init' else 'Compute'} {family.name} {mode}.",
                        "Hash API" if mode == "hash" else "XOF API",
                        mode,
                        operation,
                        accepted,
                        "HashState" if mode == "hash" and operation == "init" else "XOFState" if operation == "init" else "Output",
                    )
                )
    return tuple(result)


def api_functions(schema):
    result = [f for family in families(schema) for f in api_functions_for_family(family)]
    for mode in ("hash", "xof"):
        for name, arguments, returns, operation in (
            (f"{mode}_init", (("Parameters", f"{mode}_parameters()"),), f"{mode}_state()", "init"),
        ):
            result.append(
                Function(
                    name,
                    tuple(Argument(*a) for a in arguments),
                    returns,
                    "Initialize a native state from an algorithm atom or parameter tuple.",
                    "Hash API" if mode == "hash" else "XOF API",
                    mode,
                    operation,
                )
            )
    result.extend(
        (
            Function(
                "hash_update",
                (Argument("HashState", "hash_state()"), Argument("Input", "iodata()")),
                "hash_state()",
                "Absorb input and return a new hash state.",
                "Hash API",
                "hash",
                "update",
                result_name="NewHashState",
            ),
            Function(
                "hash_final",
                (Argument("HashState", "hash_state()"),),
                "binary()",
                "Return the output length selected during initialization.",
                "Hash API",
                "hash",
                "final",
                result_name="Output",
            ),
            Function(
                "xof_absorb",
                (Argument("XOFState", "xof_state()"), Argument("Input", "iodata()")),
                "xof_state()",
                "Absorb input and return a new absorbing state.",
                "XOF API",
                "xof",
                "absorb",
                result_name="NewXOFState",
            ),
            Function(
                "xof_squeeze",
                (Argument("XOFState", "xof_state()"), Argument("Length", "non_neg_integer()")),
                "{xof_state(), binary()}",
                "Return the advancing state and the next Length output bytes.",
                "XOF API",
                "xof",
                "squeeze",
                result_name="Result",
            ),
        )
    )
    return tuple(sorted(result, key=lambda f: (f.name, f.arity)))


def api_types(schema):
    result = [
        ("hash_state", "erlang:nif_resource()", "An immutable native hash state, with its output length chosen at initialization."),
        ("xof_state", "erlang:nif_resource()", "An immutable native absorbing or squeezing state."),
    ]
    for mode in ("hash", "xof"):
        forms = []
        algorithms = set()
        for f in families(schema):
            for fun in f.functions(mode):
                if fun.operation != "init":
                    continue
                a = " | ".join(fun.algorithms)
                algorithms.update(fun.algorithms)
                rest = [arg.type for arg in fun.arguments[1:]]
                forms.append("{" + ", ".join([a] + rest) + "}" if rest else a)
                if not rest and mode == "hash" and f.name == "keccak":
                    forms.append("{" + a + "}")
        result.extend(
            (
                (mode + "_algorithm", " | ".join(sorted(algorithms)), "Supported " + mode + " algorithm selectors."),
                (
                    mode + "_parameters",
                    " | ".join(forms),
                    "Algorithm atom or tuple containing initialization parameters in argument order.",
                ),
            )
        )
    return result


def profiles(schema, family):
    result = []
    for name in sorted(set(family.hash_algorithms + family.xof_algorithms)):
        is_xof = name in schema.xof
        profile = (
            schema.xof[name]
            if is_xof
            else (
                getattr(schema, family.name)[name]
                if family.name in ("hopmac", "kmac", "tuplehash", "parallelhash")
                else schema.hash[name]
            )
        )
        rate = (
            getattr(profile, "rate", None)
            or getattr(profile, "cshake_rate", None)
            or getattr(profile, "legacy_keccak_rate", None)
            or getattr(profile, "kt_rate", None)
            or getattr(profile, "turbo_rate", None)
            or getattr(profile, "sp800185_rate", None)
        )
        if rate is None and name != "sha2_512":
            rate = 168 if name == "shake128" else 136 if name == "shake256" else 200 - 2 * profile.max_output_len
        result.append(
            dict(
                name=name,
                rate=rate or 0,
                default=profile.default_output_len if hasattr(profile, "default_output_len") else 0,
                maximum=profile.max_output_len if hasattr(profile, "max_output_len") else None,
                hash_allowed=name in family.hash_algorithms,
                xof_allowed=name in family.xof_algorithms,
                requires_length=is_xof and family.name in ("sha3", "keccak"),
                pad=1 if family.name == "keccak" else 6 if name.startswith("sha3_") else 31,
                rounds=12 if family.name in ("kt", "hopmac", "turboshake") else 0,
            )
        )
    return tuple(result)


TITLES = {
    "sha2": "SHA-2",
    "sha3": "SHA-3 / SHAKE",
    "keccak": "legacy Keccak",
    "cshake": "cSHAKE",
    "kmac": "KMAC",
    "hopmac": "HopMAC",
    "kt": "KangarooTwelve",
    "parallelhash": "ParallelHash",
    "tuplehash": "TupleHash",
    "turboshake": "TurboSHAKE",
}


def public_doc(schema, fun):
    mode = fun.family
    if not fun.algorithms:
        return {
            "hash_init": """Initialize a hash using an algorithm atom or a parameter tuple.

Tuple fields have the same order as the corresponding `hash_init_*` function.
For example, `{kmac128, 32, Key, <<"orders/v1">>}` selects a 32-byte KMAC tag.
The output length belongs to the state; finish with `hash_final/1`.

```erlang
State0 = libdecaf:hash_init({sha3_256, 16}),
State1 = libdecaf:hash_update(State0, <<"abc">>),
<<"3A985DA74FE225B2045C172D6BD390BD">> = binary:encode_hex(libdecaf:hash_final(State1)).
```""",
            "hash_update": """Add input to a hash and return a new state.

Input accepts iodata. For TupleHash, each call adds **one complete tuple element**:
two calls with `<<"a">>` and `<<"bc">>` differ from two calls with `<<"ab">>` and `<<"c">>`.
An empty element counts; an empty one-shot list contains no elements.
The original state remains reusable, so it can be used to hash different suffixes.""",
            "hash_final": """Return the digest or authentication tag at the length chosen during initialization.

This leaves the state reusable. KMAC, TupleHash, and ParallelHash include the chosen
length in their computation: initialize at the desired length instead of truncating
a longer result. SHA-2, SHA-3, and legacy Keccak return digest prefixes when shortened.

```erlang
Key = binary:copy(<<42>>, 32),
State0 = libdecaf:hash_init_kmac(kmac128, 16, Key),
State1 = libdecaf:hash_update(State0, <<"invoice-42">>),
Tag = libdecaf:hash_final(State1),
16 = byte_size(Tag),
Tag = libdecaf:hash_kmac(kmac128, <<"invoice-42">>, 16, Key).
```""",
            "xof_init": """Initialize an XOF using an algorithm atom or a parameter tuple.

Tuple fields have the same order as the corresponding `xof_init_*` function.
Choose customization, keys, block sizes, or domain separation here; output length
is chosen later with `xof_squeeze/2`.

```erlang
State0 = libdecaf:xof_init({cshake128, <<>>, <<"orders/v1">>}),
State1 = libdecaf:xof_absorb(State0, <<"invoice-42">>),
{_State2, Output} = libdecaf:xof_squeeze(State1, 32),
Output = libdecaf:xof_cshake(cshake128, <<"invoice-42">>, 32, <<>>, <<"orders/v1">>).
```""",
            "xof_absorb": """Add input to an absorbing XOF and return a new state.

Input accepts iodata. For TupleHashXOF each call adds one whole tuple element;
for all other algorithms calls concatenate message bytes. After squeezing starts,
the returned squeezing state rejects further input, even after a zero-byte squeeze.
The original absorbing state remains reusable.""",
            "xof_squeeze": """Return `{NextState, Output}` with the next `Length` bytes of an XOF stream.

Continue with `NextState` to read subsequent bytes. Squeezing the same input state
again repeats those bytes, because states are immutable. A zero-byte squeeze still
enters the output phase. Customization is already stored by the initializer.

```erlang
State0 = libdecaf:xof_init_sha3(shake128),
State1 = libdecaf:xof_absorb(State0, [<<"a">>, <<"bc">>]),
{State2, First} = libdecaf:xof_squeeze(State1, 16),
{_State3, Second} = libdecaf:xof_squeeze(State2, 16),
Output = <<First/binary, Second/binary>>,
Output = libdecaf:xof_sha3(shake128, <<"abc">>, 32).
```""",
        }[fun.name]
    family = next(f for f in families(schema) if fun.name.endswith(f.name))
    name = family.name
    title = TITLES[name]
    parameter_doc = {
        "sha2": "SHA-512 defaults to 64 bytes. An explicit length may select a prefix from zero through 64 bytes.",
        "sha3": "SHA-3 defaults to its digest size and permits shorter prefixes. SHAKE requires an explicit hash output length.",
        "keccak": "These are the original Keccak functions, with different padding from SHA-3. Fixed digests permit prefixes; Keccak XOF selectors require an explicit hash length.",
        "cshake": "`FunctionName` and `CustomizationString` accept iodata and default to empty. With both empty, cSHAKE equals SHAKE. Use customization to separate application domains; function names are intended for named constructions.",
        "kmac": "`Key` and `CustomizationString` accept iodata; customization defaults to empty. KMAC binds the requested tag length into the result. KMACXOF uses distinct framing and produces an extensible stream. Keep keyed states private like the key. NIST-approved uses require at least 16 key bytes for KMAC128 or 32 for KMAC256.",
        "hopmac": "RFC 9861 HopMAC hashes the message and customization with KT, then uses that digest as customization for a second KT call over the key. The inner digest is 32 bytes for HopMAC128 or 64 for HopMAC256. Keep keyed states private. Shorter outputs are prefixes of the same HopMAC stream.",
        "kt": "Customization accepts iodata and defaults to empty. It is stored during initialization and appended after the message per RFC 9861. Hash defaults are 32 bytes for KT128 and 64 for KT256.",
        "parallelhash": "`BlockSize` is a positive byte count and affects the result: it must match the protocol or other implementation. Input is processed in constant memory regardless of block size. Update boundaries do not define blocks. Customization defaults to empty. ParallelHash binds the output length; ParallelHashXOF produces a distinct extensible stream. The implementation processes blocks serially.",
        "tuplehash": 'One-shot `Input` is a proper list of separate iodata elements. Each update or absorb adds one complete element. `[<<"a">>, <<"bc">>]` differs from `[<<"ab">>, <<"c">>]`; `[]` differs from `[<<>>]`. Customization defaults to empty. TupleHash binds output length; TupleHashXOF produces a distinct extensible stream.',
        "turboshake": "`DomainSeparation` is an integer from 1 through 127, defaulting to `16#1F`. It is a domain byte, rather than a customization string. Hash defaults are 32 bytes for TurboSHAKE128 and 64 for TurboSHAKE256.",
    }[name]
    values = dict(
        Type=fun.algorithms[0],
        Input='[<<"alice">>, <<"invoice-42">>]' if name == "tuplehash" else '<<"invoice-42">>',
        OutputLength="16",
        Key="binary:copy(<<42>>, 32)",
        FunctionName="<<>>",
        CustomizationString='<<"orders/v1">>',
        BlockSize="8",
        DomainSeparation="16#1F",
    )
    params = [values[a.name] for a in fun.arguments]
    call = f"libdecaf:{fun.name}(" + ", ".join(params) + ")"
    if fun.operation == "once":
        length = (
            16
            if any(a.name == "OutputLength" for a in fun.arguments)
            else next(a["default"] for a in profiles(schema, family) if a["name"] == fun.algorithms[0])
        )
        example = f"Output = {call},\n{length} = byte_size(Output)."
        lead = f"Compute {title} in one call and return output bytes."
    else:
        code = [f"State0 = {call}"]
        operation = "hash_update" if mode == "hash" else "xof_absorb"
        if name == "tuplehash":
            code += [
                f'State1 = libdecaf:{operation}(State0, <<"alice">>)',
                f'State2 = libdecaf:{operation}(State1, <<"invoice-42">>)',
            ]
            last = "State2"
        else:
            code += [f'State1 = libdecaf:{operation}(State0, [<<"invoice-">>, <<"42">>])']
            last = "State1"
        code += [
            (
                f"Output = libdecaf:hash_final({last})"
                if mode == "hash"
                else f"{{_NextState, Output}} = libdecaf:xof_squeeze({last}, 16)"
            )
        ]
        once = fun.name.replace(mode + "_init_", mode + "_")
        arguments = params[:1] + [values["Input"]] + (params[1:] if mode == "hash" else ["16"] + params[1:])
        code += [f"Output = libdecaf:{once}(" + ", ".join(arguments) + ")"]
        example = ",\n".join(code) + "."
        lead = f"Initialize {title} for incremental {'hashing' if mode == 'hash' else 'absorption and squeezing'}."
    import textwrap

    parameter_doc = textwrap.fill(parameter_doc, width=105)
    return (
        lead
        + "\n\n"
        + parameter_doc
        + "\n\nLengths are in bytes; states are immutable and must be replaced with each returned state.\n\n```erlang\n"
        + example
        + "\n```"
    )
