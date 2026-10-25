# libdecaf code generation

This development-only Python project generates committed NIF sources for libdecaf.
Normal `gmake` builds use the generated C files and do not need Python dependencies.

Requires Python 3.13 or later and Poetry 2.1 or later with the `poetry-plugin-export` plugin.
The local `reference/` directory contains copied examples and is ignored by Git.

From the repository root:

```sh
just lock       # Refresh poetry.lock and exported requirements.txt
just codegen    # Render, format, and sign generated sources
just format     # Format C, Erlang, templates, and Python sources
```

`just docker-codegen` runs generation in a Linux image built by `just docker-build`.
The image caches the locked Python dependencies separately from the host's `.venv`.
Docker helpers also cover formatting, locking, signing, and an interactive shell.

With uv installed, the pinned Poetry/export toolchain can run the lock recipe
without changing the global Poetry installation:

```sh
uvx --from 'poetry==2.5.1' --with 'poetry-plugin-export==1.10.1' just lock
```

`templates0/` renders configured definitions first. The generator then scans C
sources and headers under `c_src/nif/` for literal `ATOM(name)` references and
renders the atom table from `templates1/`. Comments, strings, macro parameters,
and the old generated atom files are excluded from discovery. Explicit atoms in
`config.yaml` preserve atoms that have no literal use in the source yet.

Change the templates or configuration and run `just codegen`; generated C is
committed so ordinary builds do not run the generator. Generated files carry a
content signature applied after formatting, and repeated generation is stable.

The first stage emits the native registration table, component implementations,
and Erlang modules. `context/crypto.py` defines the Hash/XOF argument contracts;
`config.yaml` supplies algorithms, rates, and output defaults. Functions, types,
and exports are sorted lexicographically; specs name arguments and results in
`when` clauses. Generated headers use `extern`, named parameters, and C++ linkage guards.

Each construction has a component directory: `sha2/`, `sha3/`, `keccak/`, `cshake/`,
`kmac/`, `hopmac/`, `kt/`, `tuplehash/`, `parallelhash/`, and `turboshake/`.
Both hash and XOF variants live together. Private callbacks initialize, clone,
destroy, update, finalize, and output raw contexts. Per-algorithm immutable vtables
reference these callbacks. Algorithm-specific one-shot NIFs and `_hash_init` /
`_xof_init` constructors are declared in their component header and exported in
`libdecaf_nif.erl`. Other NIF-shaped helper functions remain static.

`hash/hash.c` and `xof/xof.c` independently own their API entry points, loaders,
context structs, VM resource types, algorithm registries, and trapping lifecycles.
Each API checks only its own resource type and dispatches only to its own algorithm
descriptors. There is no shared Hash/XOF router or runtime lifecycle mode flag.
Atom tags survive code upgrades and registry reordering. Hash states retain their
chosen output length; XOF states retain an absorbing or squeezing phase.

Algorithm composition stays below these independent lifecycles: KMAC, TupleHash,
and ParallelHash call the cSHAKE initializer; HopMAC calls the KT primitive; KT
calls TurboSHAKE. The SP 800-185 integer encodings have one implementation under
`cshake/`. Include directives are emitted for the APIs used by each component.

Continuation resources own private context copies, retained input environments,
and output binaries. Input and output share a bounded reduction budget. TupleHash
charges for element framing, including empty elements; ParallelHash charges for
extra leaf permutations at small block sizes. Cancellation wipes contexts and
unpublished output. KT/HopMAC customization resources remain component-owned.

`libdecaf.erl` exposes application startup and the generic high-level interface with runnable examples
and parameter tables, followed by a Deprecated API section for the historical
top-level functions. `context/deprecated.py` maps those functions to current native
operations while preserving raw states, final-time digest truncation, SHAKE's
binary-only finalizers, and low-level curve argument order.
Generic constructors and one-shot functions expand parameter
tuples through the selected algorithm's constructor vtable. `xof/3` uses the same
parameters as `xof_init/1`, with the output byte length as its third argument.
The NIF module keeps sparse documentation. `sp800185_SUITE` checks public documentation examples and both generic and algorithm-specific native APIs.

The generated deprecated hash modules preserve tagged `{Algorithm, NativeState}`
tuples, digest truncation, SHAKE aliases, and wrapper argument errors, calling the
current native APIs directly. Prime-order group templates continue to generate
Ristretto255/Decaf448 native and Erlang implementations from `context/groups.py`.
Curve implementations and the PRNG retain their independent component resources.

Run generator checks with `cd codegen && poetry run pytest`. To run fixtures through
the actual Dialyzer and Eqwalizer:

```sh
cd codegen
LIBDECAF_TYPECHECK=1 poetry run pytest tests/test_typecheck.py
```

This requires `gmake elp` and Dialyzer. Set `LIBDECAF_TYPECHECK_PLT` to reuse a PLT.
Dialyzer checks opaque Hash/XOF state separation. Eqwalizer checks selectors and
parameter shapes but currently treats resource-backed opaque states structurally.

`just sanitizers` instruments ed448goldilocks and the NIF with ASan/UBSan, runs
upstream tests and focused suites (including all SP 800-185 vectors), and performs
10,000 resource, phase, error, and cancellation cleanup iterations.
