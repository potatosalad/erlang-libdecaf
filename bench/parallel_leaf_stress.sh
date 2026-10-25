#!/bin/sh
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gmake -C "$project_root"
mkdir -p "$project_root/logs/native"
"${CC:-cc}" -O2 -g -std=c11 -Wall -Wextra -pthread \
    -I"$project_root/c_deps/ed448goldilocks-build/src/GENERATED/include" \
    -I"$project_root/c_deps/ed448goldilocks/src/include" \
    "$project_root/bench/native/parallel_leaves.c" \
    "$project_root/c_src/nif/parallel/leaf.c" \
    "$project_root/c_deps/ed448goldilocks-build/src/libdecaf.a" \
    -o "$project_root/logs/native/parallel_leaves"
exec "$project_root/logs/native/parallel_leaves"
