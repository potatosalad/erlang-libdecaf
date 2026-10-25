# Bulk Hash/XOF throughput used by the README. No external dependencies.
# Run after gmake: elixir bench/hash_highlights.exs
# BENCH_GIB=1 BENCH_PARALLEL_GIB=32 BENCH_REPEATS=5 override message sizes/repeats.

Code.require_file("support/stream_stress.exs", __DIR__)

defmodule LibdecafBench.HashHighlights do
  def run do
    gib = positive_env("BENCH_GIB", "1")
    parallel_gib = positive_env("BENCH_PARALLEL_GIB", "32")
    repeats = positive_env("BENCH_REPEATS", "5")
    :ok = :application.set_env(:libdecaf, :parallel_absorb_rounds, 0)
    chunk = :binary.copy(<<0>>, 64 * 1024 * 1024)
    small = :binary.copy(<<0>>, 8193)

    xof_only =
      ~w(kmacxof128 kmacxof256 tuplehashxof128 tuplehashxof256 parallelhashxof128 parallelhashxof256)

    cases =
      LibdecafBench.StreamStress.cases(:hash) ++
        Enum.filter(LibdecafBench.StreamStress.cases(:xof), fn {name, _, _, _} ->
          hd(String.split(name, " / ")) in xof_only
        end)

    IO.inspect(:libdecaf_nif.keccak_info(), label: "Keccak backend")
    IO.puts("#{length(cases)} cases; #{repeats} warmed passes; 64 MiB updates.")
    IO.puts("Ordinary messages: #{gib} GiB; parallel messages: #{parallel_gib} GiB.")

    for {name, api, parameters, output_bytes} <- cases do
      expected =
        if api in [:hash, :parallel_hash],
          do: :libdecaf.hash(parameters, [small, small]),
          else: :libdecaf.xof(parameters, [small, small], output_bytes)

      ^expected = stream(api, parameters, small, 2, output_bytes)
      stream(api, parameters, chunk, 4, output_bytes)
      IO.puts("WARM #{name}")
    end

    samples =
      for round <- 1..repeats, reduce: %{} do
        acc ->
          order = if rem(round, 2) == 0, do: Enum.reverse(cases), else: cases

          Enum.reduce(order, acc, fn {name, api, parameters, output_bytes}, acc ->
            size = if api in [:parallel_hash, :parallel_xof], do: parallel_gib, else: gib

            {microseconds, _output} =
              :timer.tc(fn -> stream(api, parameters, chunk, size * 16, output_bytes) end)

            speed = size * 1024 * 1024 * 1024 / (microseconds / 1_000_000) / 1_000_000_000
            IO.puts("PASS #{round} #{name}: #{Float.round(speed, 3)} GB/s")
            Map.update(acc, name, [speed], &[speed | &1])
          end)
      end

    for {name, _, _, _} <- cases do
      values = Map.fetch!(samples, name) |> Enum.sort()
      peak = List.last(values)
      IO.puts("PEAK #{name}: #{Float.round(peak, 3)} GB/s")
    end
  end

  defp positive_env(name, default) do
    value = System.get_env(name, default) |> String.to_integer()
    if value < 1, do: raise("#{name} must be positive")
    value
  end

  defp stream(api, parameters, chunk, count, output_bytes) do
    {init, update, final} =
      case api do
        :hash -> {:hash_init, :hash_update, :hash_final}
        :parallel_hash -> {:parallel_hash_init, :parallel_hash_update, :parallel_hash_final}
        :xof -> {:xof_init, :xof_absorb, :xof_squeeze}
        :parallel_xof -> {:parallel_xof_init, :parallel_xof_absorb, :parallel_xof_squeeze}
      end

    state =
      Enum.reduce(1..count, apply(:libdecaf, init, [parameters]), fn _, state ->
        apply(:libdecaf, update, [state, chunk])
      end)

    if api in [:hash, :parallel_hash] do
      apply(:libdecaf, final, [state])
    else
      {_state, output} = apply(:libdecaf, final, [state, output_bytes])
      output
    end
  end
end

LibdecafBench.HashHighlights.run()
