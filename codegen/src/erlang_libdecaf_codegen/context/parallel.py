"""Parallel Hash and XOF contracts; leaf-capable constructions only."""

from .functions import Argument, Function
from .crypto import families, TYPES


def types(schema):
    result = []
    for mode in ("hash", "xof"):
        forms = []
        for family in families(schema):
            if family.name not in ("kt", "hopmac", "parallelhash"):
                continue
            names = getattr(family, mode + "_algorithms")
            for form in getattr(family, mode + "_forms"):
                algorithm = " | ".join(sorted(names))
                if names:
                    forms.append("{" + ", ".join((algorithm, *(TYPES[arg] for arg in form))) + "}" if form else algorithm)
        result += [
            (
                f"parallel_{mode}_parameters",
                " | ".join(forms) or "none()",
                "Initialization parameters for KT, HopMAC, and ParallelHash constructions supporting parallel leaves.",
            ),
            (
                f"parallel_{mode}_state",
                "erlang:nif_resource()",
                f"An immutable parallel {mode.upper()} state. Retain each returned state to advance the stream.",
            ),
            (
                f"parallel_{mode}_operation",
                "erlang:nif_resource()",
                f"A pending parallel {mode.upper()} operation, private to its calling process.",
            ),
        ]
    return tuple(sorted(result))


def functions(schema, public=False):
    result = []
    for mode, title, update, finish in (("hash", "Hash", "update", "final"), ("xof", "XOF", "absorb", "squeeze")):
        state = f"parallel_{mode}_state()"
        parameters = f"parallel_{mode}_parameters()"
        operation = f"parallel_{mode}_operation()"
        await_type = f"{{await, reference(), {operation}}}"
        docs = {
            "init": f"""Initialize a parallel {title} state.

Accepts the same parameter forms as `{mode}_init/1` for KT128/KT256,
HopMAC128/HopMAC256, and {'ParallelHash128/ParallelHash256' if mode == 'hash' else 'ParallelHashXOF128/ParallelHashXOF256'}.
Other algorithms raise `badarg`. KT and HopMAC use 8192-byte leaves;
ParallelHash uses its configured block size. States remain immutable.

```erlang
S0 = libdecaf:parallel_{mode}_init({'{parallelhash128, 32, 8192}' if mode == 'hash' else '{parallelhashxof128, 8192}'}),
S1 = libdecaf:parallel_{mode}_{update}(S0, <<"invoice-42">>),
{'Output = libdecaf:parallel_hash_final(S1).' if mode == 'hash' else '{_S2, Output} = libdecaf:parallel_xof_squeeze(S1, 32).'}
```""",
            update: f"""Add input to a parallel {title} state and return its new state.

The NIF tops up a partial leaf before dispatching full blocks to the routers.
Binary payloads are retained once and jobs use offsets; iodata is normalized
once. Workers compute leaves independently, and the caller joins chaining
values in input order. The Erlang wrapper waits for native completion messages.
Work and result storage grow with the input, up to 4096 leaves per operation at a time.
If the router pool is disabled, the caller performs the work on a dirty scheduler.
The previous state remains reusable, including from other processes.""",
            finish: (
                """Return the configured hash output without changing the input state.

```erlang
State = libdecaf:parallel_hash_update(libdecaf:parallel_hash_init(kt128), <<"abc">>),
Digest = libdecaf:parallel_hash_final(State),
Digest = libdecaf:hash(kt128, <<"abc">>).
```"""
                if mode == "hash"
                else """Read output and return `{NextState, Output}`.

The returned state can keep squeezing, but cannot absorb further input.
The input state remains reusable. Output lengths are in bytes.

```erlang
S0 = libdecaf:parallel_xof_absorb(libdecaf:parallel_xof_init(kt128), <<"abc">>),
{S1, First} = libdecaf:parallel_xof_squeeze(S0, 32),
{_S2, Next} = libdecaf:parallel_xof_squeeze(S1, 32),
Combined = <<First/binary, Next/binary>>,
Combined = libdecaf:xof(kt128, <<"abc">>, 64).
```"""
            ),
            "once": f"""Compute {'a parallel hash' if mode == 'hash' else 'parallel XOF output'} from initialization parameters and input.

Uses the same framing and produces the same bytes as `{mode}/{'2' if mode == 'hash' else '3'}`.
Parallelism applies to independent leaves, without changing the algorithm.

```erlang
Input = binary:copy(<<"abc">>, 10000),
Output = libdecaf:parallel_{mode}(kt128, Input{'' if mode == 'hash' else ', 64'}),
Output = libdecaf:{mode}(kt128, Input{'' if mode == 'hash' else ', 64'}).
```""",
        }
        entries = [
            (f"parallel_{mode}_init", (("Parameters", parameters),), state, "init", "State"),
            (f"parallel_{mode}_{update}", (("State", state), ("Input", "input()")), state, update, "NewState"),
            (
                f"parallel_{mode}_{finish}",
                (("State", state),) + (() if mode == "hash" else (("OutputLength", "output_length()"),)),
                "binary()" if mode == "hash" else f"{{{state}, binary()}}",
                finish,
                "Output" if mode == "hash" else "Result",
            ),
            (
                f"parallel_{mode}",
                (("Parameters", parameters), ("Input", "input()"))
                + (() if mode == "hash" else (("OutputLength", "output_length()"),)),
                "binary()",
                "once",
                "Output",
            ),
        ]
        if not public:
            entries.append((f"parallel_{mode}_continue", (("Operation", operation),), f"{state} | binary()", "continue", "Result"))
        for name, args, returns, action, result_name in entries:
            if not public and action in (update, "once", "continue"):
                completed = f"{{done, reference(), {state}}}"
                finalized = f"{{finalize, reference(), {state}, output_length()}}"
                returns = " | ".join((completed, finalized, await_type))
            doc = docs.get(action, "Collect completed parallel leaves, dispatch more work, and continue an owned operation.")
            if not public and action in (update, "once", "continue"):
                doc = "Return `{done, Reference, State}`, `{finalize, Reference, State, Length}`, or\n`{await, Reference, Operation}`. On `{libdecaf_parallel, Reference}`, call the\nmatching continuation. `finalize` requests hash finalization or XOF output.\nPolling also recovers unavailable routers. See libdecaf for synchronous wrappers."
            result.append(
                Function(
                    name,
                    tuple(Argument(*arg) for arg in args),
                    returns,
                    doc,
                    title + " API",
                    mode,
                    "parallel_" + action,
                    result_name=result_name,
                )
            )
    return tuple(sorted(result, key=lambda f: (f.name, f.arity)))
