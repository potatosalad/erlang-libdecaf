# libdecaf code generation

This development-only Python project generates committed NIF sources for libdecaf.
Normal `gmake` builds use the generated C files and do not need Python dependencies.

Requires Python 3.13 or later and Poetry 2.x with the `poetry-plugin-export` plugin.
The local `reference/` directory contains copied examples and is ignored by Git.
