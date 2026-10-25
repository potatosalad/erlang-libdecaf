# Warmed, repeated parallel Hash measurements for the README highlights.
# Run from the repository root after gmake:
#   elixir bench/parallel_hash_highlights.exs
# GB/s uses decimal gigabytes; GiB/MiB settings describe binary input sizes.

Code.prepend_path(Path.expand("ebin"))
{:ok, _} = :libdecaf.start()
:ok = :application.set_env(:libdecaf, :parallel_absorb_rounds, 0)
gib = System.get_env("BENCH_GIB", "32") |> String.to_integer()
repeats = System.get_env("BENCH_REPEATS", "7") |> String.to_integer()
if gib < 1 or repeats < 1, do: raise("BENCH_GIB and BENCH_REPEATS must be positive")

chunk = :binary.copy(<<0>>, 64 * 1024 * 1024)
key = :binary.copy(<<0>>, 32)
customization = :binary.copy(<<0>>, 32)

cases = [
  {"KT128", {:kt128, 32}},
  {"KT256", {:kt256, 64}},
  {"HopMAC128", {:hopmac128, 32, key, customization}},
  {"HopMAC256", {:hopmac256, 64, key, customization}},
  {"ParallelHash128", {:parallelhash128, 32, 8192}},
  {"ParallelHash256", {:parallelhash256, 64, 8192}}
]

hash = fn parameters, count ->
  state =
    Enum.reduce(1..count, :libdecaf.parallel_hash_init(parameters), fn _, state ->
      :libdecaf.parallel_hash_update(state, chunk)
    end)

  :libdecaf.parallel_hash_final(state)
end

for {_, parameters} <- cases, do: hash.(parameters, 16)

samples =
  for round <- 1..repeats, reduce: %{} do
    acc ->
      order = if rem(round, 2) == 0, do: Enum.reverse(cases), else: cases

      Enum.reduce(order, acc, fn {name, parameters}, acc ->
        {microseconds, _} = :timer.tc(fn -> hash.(parameters, gib * 16) end)
        speed = gib * 1024 * 1024 * 1024 / (microseconds / 1_000_000) / 1_000_000_000
        IO.puts("#{round} #{name} #{Float.round(speed, 3)} GB/s")
        Map.update(acc, name, [speed], &[speed | &1])
      end)
  end

for {name, _} <- cases do
  values = Map.fetch!(samples, name) |> Enum.sort()
  middle = div(repeats, 2)

  median =
    if rem(repeats, 2) == 0,
      do: (Enum.at(values, middle - 1) + Enum.at(values, middle)) / 2,
      else: Enum.at(values, middle)

  IO.puts(
    "MEDIAN #{name}: #{Float.round(median, 3)} GB/s; range #{Float.round(hd(values), 3)}–#{Float.round(List.last(values), 3)}"
  )
end
