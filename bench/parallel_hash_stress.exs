# Large-batch throughput; keep hash_stress.exs for the 1 MiB update workload.
# Run from the repository root:
#   gmake && elixir bench/parallel_hash_stress.exs
#   BENCH_MIB=64 BENCH_ROUNDS=100 BENCH_TIME=20 elixir bench/parallel_hash_stress.exs
#   BENCH_MIB=1 elixir bench/parallel_hash_stress.exs

Mix.install([{:benchee, "~> 1.5.1"}])

Code.prepend_path(Path.expand("../ebin", __DIR__))
{:ok, _} = :application.ensure_all_started(:libdecaf)

gib = System.get_env("BENCH_GIB", "4") |> String.to_integer()
mib = System.get_env("BENCH_MIB", "32") |> String.to_integer()
time = System.get_env("BENCH_TIME", "10") |> String.to_integer()
rounds = System.get_env("BENCH_ROUNDS", "0") |> String.to_integer()
callers = System.get_env("BENCH_CALLERS", "1") |> String.to_integer()

if gib < 1 or mib < 1 or time < 1 or rounds < 0 or callers < 1,
  do:
    raise(
      "BENCH_GIB, BENCH_MIB, BENCH_TIME, and BENCH_CALLERS must be positive; BENCH_ROUNDS may be zero"
    )

if rem(gib * 1024, mib) != 0,
  do: raise("BENCH_MIB must divide BENCH_GIB * 1024 exactly")

:ok = :application.set_env(:libdecaf, :parallel_absorb_rounds, rounds)
chunk = :binary.copy(<<0>>, mib * 1024 * 1024)
updates = div(gib * 1024, mib)

defmodule ParallelHashStress do
  def hash(parameters, chunk, updates) do
    state = :libdecaf.parallel_hash_init(parameters)

    state =
      Enum.reduce(1..updates, state, fn _, state ->
        :libdecaf.parallel_hash_update(state, chunk)
      end)

    :libdecaf.parallel_hash_final(state)
  end

  def xof(parameters, chunk, updates) do
    state = :libdecaf.parallel_xof_init(parameters)

    state =
      Enum.reduce(1..updates, state, fn _, state ->
        :libdecaf.parallel_xof_absorb(state, chunk)
      end)

    {_state, output} = :libdecaf.parallel_xof_squeeze(state, 32)
    output
  end

  def report(suite, gib) do
    IO.puts("\nCompleted-message throughput (GiB/s per caller; aggregate includes all callers):")

    IO.puts(
      :io_lib.format("~-45s ~12s ~12s ~8s ~10s", [
        "Algorithm / API",
        "GiB/s",
        "Aggregate",
        "Passes",
        "Total GiB"
      ])
    )

    for scenario <- suite.scenarios do
      stats = scenario.run_time_data.statistics
      per_caller = gib * stats.ips

      IO.puts(
        :io_lib.format("~-45s ~12.3f ~12.3f ~8B ~10B", [
          scenario.name,
          per_caller,
          per_caller * suite.configuration.parallel,
          stats.sample_size,
          stats.sample_size * gib
        ])
      )
    end
  end
end

# Validate the whole configured chunk outside the timed, multi-gigabyte passes.
for {hash, xof} <- [
      {{:kt128, 32}, :kt128},
      {{:parallelhash128, 32, 8192}, {:parallelhashxof128, 8192}}
    ] do
  expected = :libdecaf.hash(hash, chunk)
  ^expected = ParallelHashStress.hash(hash, chunk, 1)
  expected_xof = :libdecaf.xof(xof, chunk, 32)
  ^expected_xof = ParallelHashStress.xof(xof, chunk, 1)
end

IO.puts(
  "Each pass streams #{gib} GiB in #{mib} MiB updates (#{updates} updates), producing 32 bytes."
)

IO.puts("Worker budget: #{rounds} leaves (0 drains until idle); concurrent callers: #{callers}.")
IO.puts("Input storage is reused; all reported samples finish the entire message.")

Benchee.run(
  %{
    "kt128 / parallel_hash" => fn -> ParallelHashStress.hash({:kt128, 32}, chunk, updates) end,
    "kt128 / parallel_xof" => fn -> ParallelHashStress.xof(:kt128, chunk, updates) end,
    "parallelhash128 (8 KiB) / parallel_hash" => fn ->
      ParallelHashStress.hash({:parallelhash128, 32, 8192}, chunk, updates)
    end,
    "parallelhashxof128 (8 KiB) / parallel_xof" => fn ->
      ParallelHashStress.xof({:parallelhashxof128, 8192}, chunk, updates)
    end
  },
  time: time,
  warmup: 1,
  parallel: callers,
  formatters: [fn suite -> ParallelHashStress.report(suite, gib) end],
  pre_check: false
)
