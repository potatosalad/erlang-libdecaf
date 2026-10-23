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
`config.yaml` supplies algorithms, rates, and output defaults. `context/functions.py`
contains the remaining primitive contracts. Functions, types, and exports are sorted
lexicographically; specs name arguments and results in `when` clauses.

Native components own their resource loaders, state destructors, and continuation
resources. Curves live under `curve25519/` and `curve448/`, the PRNG under `csprng/`,
and hash constructions under `hash/`, `kmac/`, `tuplehash/`, `parallelhash/`, and `xof/`.
Curve folders do not add prefixes to native symbols. `libdecaf_nif.c` includes headers,
registers entry points, and calls loaders on initial load and upgrade.

`hash/hash.c` dispatches `hash_update`, `hash_final`, `xof_absorb`, and `xof_squeeze`
to the component owning the resource. Generic initializers only expand parameter
tuples into family initializers. Algorithm selection and parameters stay local
to the owning component. Hash states retain their chosen output length; XOF states
retain an advancing output cursor. Hash/XOF resources reject the other lifecycle.

`xof/api_family.c.inc` and `xof/api_lifecycle.c.inc` generate ordinary C functions,
with component-specific names in sanitizer reports and stack traces. There are no
C template-instantiation macros, shared state unions, or algorithm operation tables.
Input and output share a bounded reduction budget. ParallelHash charges for the
extra leaf permutations needed for small block sizes. TupleHash charges for element
framing, including empty elements. Traps own their private contexts, retained inputs,
and output binaries; destructors wipe and release them after cancellation.

KT and HopMAC retain customization in immutable native resources, appending it
only after the message. HopMAC computes the RFC 9861 inner digest (32/64 bytes)
and uses it as customization for the outer keyed KT invocation. KMAC, TupleHash,
and ParallelHash encode the chosen hash length, or zero for their XOF variants.
ParallelHash streams its leaves without a block-sized allocation. The implementation
processes leaves serially.

The public `libdecaf.erl` template explains these lifecycles and generates runnable
examples for every one-shot and initializer. `libdecaf_nif.erl` keeps sparse native
documentation. Both use the same exports and named-variable typespecs. Native
Markdown documentation requires OTP 27 or later; CI exercises OTP 28 and OTP 29.
`sp800185_SUITE` executes the public function documentation examples.

The generated deprecated `libdecaf_sha2`, `libdecaf_sha3`, and
`libdecaf_keccak_sha3` modules preserve `{Algorithm, NativeState}` tuples and old
truncation/SHAKE behavior, calling the current native APIs directly. They direct
new callers to `libdecaf`.

`context/groups.py` and the prime-order templates generate Ristretto255 and Decaf448
native implementations and documented Erlang modules. Their precomputation tables
have independent resource lifecycles. No group-instantiation C macros are used.

Run generator checks with `cd codegen && poetry run pytest`. To run positive and
intentionally invalid fixtures through the actual Dialyzer and Eqwalizer:

```sh
cd codegen
LIBDECAF_TYPECHECK=1 poetry run pytest tests/test_typecheck.py
```

This requires `gmake elp` and an installed Dialyzer. Set `LIBDECAF_TYPECHECK_PLT`
to reuse a PLT for the current OTP. Dialyzer checks Hash/XOF opaque state separation;
Eqwalizer currently treats resource-backed opaque states structurally, but checks
selectors, tuple forms, keys, block sizes, domain bytes, and tuple-element lists.
Native checks enforce state and phase separation independently of static analysis.

`just sanitizers` instruments both ed448goldilocks and the NIF with ASan/UBSan,
runs upstream tests and focused suites (including all SP 800-185 vectors), and
performs 10,000 resource/phase/error cleanup iterations across all XOF families.
