# Run from the repository root:
#   gmake && elixir bench/xof.exs
#   BENCH_BYTES=65536 BENCH_TIME=1 elixir bench/xof.exs
# Default: 1 MiB messages, 0.1 seconds per case, no per-case warmup.
# Includes matching crypto algorithms available in the current runtime.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.require_file("support/one_shot.exs", __DIR__)

LibdecafBench.OneShot.run(:xof)
