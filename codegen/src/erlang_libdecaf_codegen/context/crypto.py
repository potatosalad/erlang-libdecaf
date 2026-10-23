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
        return self.name

    @property
    def basename(self):
        return self.name

    @property
    def header(self):
        return self.directory + "/" + self.basename + ".h"

    def functions(self, mode):
        return tuple(f for f in api_functions_for_family(self) if f.family == mode)


TYPES = {
    "OutputLength": "output_length()",
    "FunctionName": "function_name()",
    "CustomizationString": "customization_string()",
    "Key": "key()",
    "BlockSize": "block_size()",
    "DomainSeparation": "domain_separation()",
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
        if not algorithms:
            continue
        for form in forms:
            accepted = algorithms
            if mode == "hash" and not form and family.name in ("sha3", "keccak"):
                accepted = tuple(n for n in algorithms if n.startswith("sha3_") or n.startswith("keccak_"))
            if not accepted:
                continue
            algtype = " | ".join(accepted)
            initargs = (("Type", algtype),) + tuple((p, TYPES[p]) for p in form)
            onceform = form if mode == "hash" else ("OutputLength",) + form
            onceargs = (("Type", algtype), ("Input", "tuple_input()" if family.name == "tuplehash" else "input()")) + tuple(
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


def family_functions(schema):
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
                (Argument("HashState", "hash_state()"), Argument("Input", "input()")),
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
                (Argument("XOFState", "xof_state()"), Argument("Input", "input()")),
                "xof_state()",
                "Absorb input and return a new absorbing state.",
                "XOF API",
                "xof",
                "absorb",
                result_name="NewXOFState",
            ),
            Function(
                "xof_squeeze",
                (Argument("XOFState", "xof_state()"), Argument("Length", "output_length()")),
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
        ("block_size", "pos_integer()", "ParallelHash block size in bytes. It is part of the construction and changes the digest."),
        ("customization_string", "iodata()", "Application-specific domain separation string; the default is empty."),
        ("domain_separation", "1..127", "TurboSHAKE domain byte, defaulting to 16#1F."),
        ("function_name", "iodata()", "cSHAKE function-name string; the default is empty."),
        ("input", "iodata()", "Message bytes accepted as iodata, or one complete TupleHash element during absorption."),
        ("key", "iodata()", "Secret KMAC or HopMAC key material accepted as iodata."),
        ("output_length", "non_neg_integer()", "Requested number of output bytes, including zero."),
        ("tuple_input", "[iodata()]", "A proper list of separately framed TupleHash elements."),
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
    output_forms = []
    for family in families(schema):
        for fun in api_functions_for_family(family):
            if fun.family == "xof" and fun.operation == "once":
                output_forms.append("{" + ", ".join([" | ".join(fun.algorithms)] + [arg.type for arg in fun.arguments[2:]]) + "}")
    result.append(
        ("xof_output_parameters", " | ".join(output_forms), "Algorithm, output byte length, and optional XOF parameters.")
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


def family_doc(schema, fun):
    mode = fun.family
    if not fun.algorithms:
        return {
            "hash_init": """Initialize a hash using an algorithm atom or a parameter tuple.

Tuple fields put the algorithm first, then output length and construction-specific options.
For example, `{kmac128, 32, Key, <<"orders/v1">>}` selects a 32-byte KMAC tag.
The output length belongs to the state; finish with `hash_final/1`.

Parameter forms (`L` is output bytes, `S` is customization, and `B` is block bytes):

| Algorithms | Parameters |
| --- | --- |
| SHA-2, SHA-3, fixed Keccak | `Algorithm` or `{Algorithm, L}` |
| SHAKE, Keccak XOF | `{Algorithm, L}` |
| cSHAKE | `{Algorithm, L}` or `{Algorithm, L, FunctionName, S}` |
| KMAC, HopMAC | `{Algorithm, L, Key}` or `{Algorithm, L, Key, S}` |
| KT | `Algorithm`, `{Algorithm, L}`, or `{Algorithm, L, S}` |
| TurboSHAKE | `Algorithm`, `{Algorithm, L}`, or `{Algorithm, L, Domain}` |
| TupleHash | `{Algorithm, L}` or `{Algorithm, L, S}` |
| ParallelHash | `{Algorithm, L, B}` or `{Algorithm, L, B, S}` |

SHA-2, SHA-3, and fixed Keccak permit prefixes up to the full digest size.
KT and TurboSHAKE default to 32 bytes at strength 128 and 64 at strength 256.
TurboSHAKE's domain is an integer in `1..127`, defaulting to `16#1F`.
ParallelHash's positive block size affects the digest; update boundaries do not.
Blocks are processed serially in constant memory. Keys and customization accept
iodata; omitted customization and function names are empty.

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
State0 = libdecaf:hash_init({kmac128, 16, Key}),
State1 = libdecaf:hash_update(State0, <<"invoice-42">>),
Tag = libdecaf:hash_final(State1),
16 = byte_size(Tag),
Tag = libdecaf:hash({kmac128, 16, Key}, <<"invoice-42">>).
```""",
            "xof_init": """Initialize an XOF using an algorithm atom or a parameter tuple.

Tuple fields put the algorithm first, followed by its construction-specific options.
Choose customization, keys, block sizes, or domain separation here; output length
is chosen later with `xof_squeeze/2`.

| Algorithms | Parameters |
| --- | --- |
| SHAKE, Keccak XOF | `Algorithm` |
| cSHAKE | `Algorithm` or `{Algorithm, FunctionName, Customization}` |
| KMACXOF, HopMAC | `{Algorithm, Key}` or `{Algorithm, Key, Customization}` |
| KT, TupleHashXOF | `Algorithm` or `{Algorithm, Customization}` |
| TurboSHAKE | `Algorithm` or `{Algorithm, Domain}` |
| ParallelHashXOF | `{Algorithm, BlockSize}` or `{Algorithm, BlockSize, Customization}` |

Use `kmacxof128`, `kmacxof256`, `tuplehashxof128`, `tuplehashxof256`,
`parallelhashxof128`, and `parallelhashxof256` selectors for these XOF variants. They produce different output from their
length-bound hash variants. Other XOF families are SHAKE, cSHAKE, Keccak XOF,
KT, TurboSHAKE, and HopMAC, each at strength 128 or 256.
Function names, keys, and customization accept iodata; empty cSHAKE strings yield
SHAKE output. TurboSHAKE uses an integer domain in `1..127`, default `16#1F`.
Keep KMACXOF and HopMAC states private like their keys.

```erlang
State0 = libdecaf:xof_init({cshake128, <<>>, <<"orders/v1">>}),
State1 = libdecaf:xof_absorb(State0, <<"invoice-42">>),
{_State2, Output} = libdecaf:xof_squeeze(State1, 32),
Output = libdecaf:xof({cshake128, 32, <<>>, <<"orders/v1">>}, <<"invoice-42">>).
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
State0 = libdecaf:xof_init(shake128),
State1 = libdecaf:xof_absorb(State0, [<<"a">>, <<"bc">>]),
{State2, First} = libdecaf:xof_squeeze(State1, 16),
{_State3, Second} = libdecaf:xof_squeeze(State2, 16),
Output = <<First/binary, Second/binary>>,
Output = libdecaf:xof({shake128, 32}, <<"abc">>).
```""",
        }[fun.name]


@dataclass(frozen=True)
class NativeAlgorithm:
    family: Family
    profile: dict

    @property
    def name(self):
        return self.profile["name"]

    @property
    def symbol(self):
        return "libdecaf_nif_" + self.name

    def functions(self, mode=None, operation=None):
        result = []
        for fun in api_functions_for_family(self.family):
            if self.name not in fun.algorithms:
                continue
            if mode is not None and fun.family != mode:
                continue
            if operation is not None and fun.operation != operation:
                continue
            name = self.name + ("_" + fun.family + "_init" if fun.operation == "init" else "")
            result.append(
                Function(
                    name,
                    fun.arguments[1:],
                    fun.returns,
                    fun.doc.replace(self.family.name, self.name),
                    fun.group,
                    fun.family,
                    fun.operation,
                    (self.name,),
                    fun.result_name,
                )
            )
        return tuple(result)

    @property
    def exports(self):
        result = {}
        for fun in self.functions():
            result.setdefault((fun.name, fun.arity), fun)
        return tuple(sorted(result.values(), key=lambda f: (f.name, f.arity)))


def native_algorithms(schema):
    return tuple(sorted((NativeAlgorithm(f, p) for f in families(schema) for p in profiles(schema, f)), key=lambda a: a.name))


def generic_functions(schema):
    result = [f for f in family_functions(schema) if not f.algorithms]
    result += [
        Function(
            "hash",
            (Argument("Parameters", "hash_parameters()"), Argument("Input", "input() | tuple_input()")),
            "binary()",
            "Compute a hash from initialization parameters and input.",
            "Hash API",
            "hash",
            "once",
            result_name="Output",
        ),
        Function(
            "xof",
            (Argument("Parameters", "xof_output_parameters()"), Argument("Input", "input() | tuple_input()")),
            "binary()",
            "Compute XOF bytes from an algorithm/output-length tuple and input.",
            "XOF API",
            "xof",
            "once",
            result_name="Output",
        ),
        Function(
            "xof",
            (
                Argument("Parameters", "xof_parameters()"),
                Argument("Input", "input() | tuple_input()"),
                Argument("OutputLength", "output_length()"),
            ),
            "binary()",
            "Compute OutputLength XOF bytes using initialization parameters.",
            "XOF API",
            "xof",
            "once",
            result_name="Output",
        ),
    ]
    return tuple(result)


def api_functions(schema):
    return tuple(
        sorted(
            [f for a in native_algorithms(schema) for f in a.exports] + list(generic_functions(schema)),
            key=lambda f: (f.name, f.arity),
        )
    )


def public_functions(schema):
    return tuple(sorted(generic_functions(schema), key=lambda f: (f.name, f.arity)))


def public_doc(schema, fun):
    if fun.name == "hash":
        return """Hash input using an algorithm atom or initialization parameter tuple.

Tuple fields match `hash_init/1`. For TupleHash, input is a list of separate elements.

```erlang
Output = libdecaf:hash({parallelhash128, 32, 8192, <<"orders/v1">>}, <<"invoice-42">>),
State = libdecaf:hash_update(libdecaf:hash_init({parallelhash128, 32, 8192, <<"orders/v1">>}), <<"invoice-42">>),
Output = libdecaf:hash_final(State).
```"""
    if fun.name == "xof":
        if fun.arity == 2:
            return """Return XOF bytes using `{Algorithm, OutputLength, ...Options}` and input.

The tuple places the output byte count immediately after the algorithm. Remaining
fields have the same order as the algorithm's XOF initializer. TupleHashXOF input
is a list of separate elements. The result is a binary, not a state.

```erlang
Output = libdecaf:xof({parallelhashxof128, 32, 8192, <<"orders/v1">>}, <<"invoice-42">>),
State = libdecaf:xof_absorb(libdecaf:xof_init({parallelhashxof128, 8192, <<"orders/v1">>}), <<"invoice-42">>),
{_Next, Output} = libdecaf:xof_squeeze(State, 32).
```"""
        return """Return `OutputLength` bytes using XOF initialization parameters and input.

The parameter atom or tuple is identical to `xof_init/1`; output length is supplied
separately. For TupleHashXOF, input is a list of separate elements.

```erlang
Output = libdecaf:xof({cshake128, <<>>, <<"orders/v1">>}, <<"invoice-42">>, 32),
Output = libdecaf:xof({cshake128, 32, <<>>, <<"orders/v1">>}, <<"invoice-42">>).
```"""
    return family_doc(schema, fun)
