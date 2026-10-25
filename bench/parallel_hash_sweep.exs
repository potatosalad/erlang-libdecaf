# Compare update sizes while keeping the compiled native leaf window unchanged.
#   gmake && BENCH_GIB=16 elixir bench/parallel_hash_sweep.exs
#   BENCH_GIB=16 BENCH_MIBS='16 32 64' elixir bench/parallel_hash_sweep.exs
# Repeat on an otherwise idle machine before choosing a ceiling profile.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.require_file("support/stream_stress.exs", __DIR__)

sizes =
  System.get_env("BENCH_MIBS", "4 8 16 32 64 128")
  |> String.split()
  |> Enum.map(&String.to_integer/1)

if sizes == [] or Enum.any?(sizes, &(&1 < 1)),
  do: raise("BENCH_MIBS must contain positive MiB sizes separated by spaces")

for mib <- sizes do
  System.put_env("BENCH_MIB", Integer.to_string(mib))
  IO.puts("\n=== #{mib} MiB updates ===")
  LibdecafBench.StreamStress.run(:parallel_hash)
end
