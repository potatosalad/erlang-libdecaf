# Reuse the algorithm catalog; loading this module does not run a streaming suite.
Code.require_file("stream_stress.exs", __DIR__)
Code.require_file("grouped_console.exs", __DIR__)

defmodule LibdecafBench.OneShot do
  def run(api) do
    bytes = System.get_env("BENCH_BYTES", "1048576") |> String.to_integer()
    {time, ""} = System.get_env("BENCH_TIME", "0.1") |> Float.parse()
    rounds = System.get_env("BENCH_ROUNDS", "0") |> String.to_integer()

    if bytes < 0 or time <= 0 or rounds < 0,
      do: raise("BENCH_BYTES and BENCH_ROUNDS must be nonnegative; BENCH_TIME must be positive")

    :ok = :application.set_env(:libdecaf, :parallel_absorb_rounds, rounds)
    message = :binary.copy(<<0>>, bytes)

    jobs =
      Map.new(LibdecafBench.StreamStress.cases(api), fn
        {name, implementation, parameters, output_bytes} ->
          [algorithm, _api] = String.split(name, " / ")
          input = if String.starts_with?(algorithm, "tuplehash"), do: [message], else: message
          function = job(implementation, parameters, input, output_bytes)

          # Check output lengths and parallel equivalence outside measurement.
          output = function.()
          ^output_bytes = byte_size(output)

          if implementation in [:parallel_hash, :parallel_xof] do
            expected = job(api, parameters, input, output_bytes).()
            ^expected = output
          end

          {"#{algorithm} / one-shot / #{implementation}", function}
      end)

    IO.puts("One-shot #{api}: #{map_size(jobs)} cases, #{bytes}-byte messages, one caller.")
    IO.puts("Message allocation is outside timing; TupleHash receives one tuple element.")
    IO.puts("Parallel worker budget: #{rounds} leaves (0 drains until idle).")

    Benchee.run(jobs,
      time: time,
      warmup: 0,
      parallel: 1,
      pre_check: false,
      formatters: [fn suite -> report(suite, bytes) end]
    )
  end

  defp job(:hash, parameters, input, _length),
    do: fn -> :libdecaf.hash(parameters, input) end

  defp job(:parallel_hash, parameters, input, _length),
    do: fn -> :libdecaf.parallel_hash(parameters, input) end

  defp job(:xof, parameters, input, length),
    do: fn -> :libdecaf.xof(parameters, input, length) end

  defp job(:parallel_xof, parameters, input, length),
    do: fn -> :libdecaf.parallel_xof(parameters, input, length) end

  defp report(suite, bytes) do
    suite.scenarios
    |> Enum.group_by(fn scenario -> hd(String.split(scenario.name, " / ")) end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.each(fn {_algorithm, scenarios} ->
      group = Benchee.relative_statistics(%{suite | scenarios: scenarios})
      Benchee.Formatter.output(group, LibdecafBench.GroupedConsole)

      rates =
        Enum.map_join(group.scenarios, " | ", fn scenario ->
          implementation = List.last(String.split(scenario.name, " / "))
          rate = bytes * scenario.run_time_data.statistics.ips / (1024 * 1024)
          "#{implementation}: #{:erlang.float_to_binary(rate, decimals: 2)}"
        end)

      IO.puts("\nThroughput (MiB/s): #{rates}")
    end)
  end
end
