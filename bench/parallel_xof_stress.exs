# Run from the repository root:
#   gmake && elixir bench/parallel_xof_stress.exs
#   BENCH_GIB=8 BENCH_MIB=32 elixir bench/parallel_xof_stress.exs
# One complete pass per case per caller; BENCH_TIME is no longer used.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.require_file("support/stream_stress.exs", __DIR__)

LibdecafBench.StreamStress.run(:parallel_xof)
