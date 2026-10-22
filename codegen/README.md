# libdecaf code generation

This development-only Python project generates committed NIF sources for libdecaf.
Normal `gmake` builds use the generated C files and do not need Python dependencies.

Requires Python 3.13 or later and Poetry 2.x with the `poetry-plugin-export` plugin.
The local `reference/` directory contains copied examples and is ignored by Git.

From the repository root:

```sh
just lock       # Refresh poetry.lock and exported requirements.txt
just codegen    # Render, format, and sign generated sources
just format     # Format C, Erlang, templates, and Python sources
```

`templates0/` renders configured definitions first. The generator then scans C
sources and headers under `c_src/nif/` for literal `ATOM(name)` references and
renders the atom table from `templates1/`. Comments, strings, macro parameters,
and the old generated atom files are excluded from discovery. Explicit atoms in
`config.yaml` preserve atoms that have no literal use in the source yet.

Change the templates or configuration and run `just codegen`; generated C is
committed so ordinary builds do not run the generator. Generated files carry a
content signature applied after formatting, and repeated generation is stable.
