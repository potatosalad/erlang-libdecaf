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
    crypto_hashes = :crypto.supports(:hashs)

    jobs =
      Enum.reduce(LibdecafBench.StreamStress.cases(api), %{}, fn
        {name, implementation, parameters, output_bytes}, jobs ->
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

          jobs = Map.put(jobs, "#{algorithm} / one-shot / libdecaf:#{implementation}", function)

          # Add each crypto baseline once, alongside the regular libdecaf case.
          if implementation == api do
            case crypto_job(parameters, input, output_bytes, crypto_hashes) do
              nil ->
                jobs

              {label, crypto_function} ->
                ^output = crypto_function.()
                Map.put(jobs, "#{algorithm} / one-shot / #{label}", crypto_function)
            end
          else
            jobs
          end
      end)

    IO.puts("One-shot #{api}: #{map_size(jobs)} cases, #{bytes}-byte messages, one caller.")
    IO.puts("Message allocation is outside timing; TupleHash receives one tuple element.")
    IO.puts("Available crypto equivalents are included and checked for identical output.")
    IO.puts("Parallel worker budget: #{rounds} leaves (0 drains until idle).")
    IO.inspect(:crypto.info_lib(), label: "crypto backend")

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

  defp crypto_job(parameters, input, output_bytes, supported) do
    algorithm =
      case parameters do
        :sha2_512 ->
          :sha512

        {shake, _length} when shake in [:shake128, :shake256] ->
          shake

        algorithm
        when algorithm in [:sha3_224, :sha3_256, :sha3_384, :sha3_512, :shake128, :shake256] ->
          algorithm

        _ ->
          nil
      end

    if algorithm in supported do
      if algorithm in [:shake128, :shake256] do
        if function_exported?(:crypto, :hash_xof, 3) do
          # crypto uses bits, while libdecaf uses bytes.
          bits = output_bytes * 8
          {"crypto:hash_xof", fn -> :crypto.hash_xof(algorithm, input, bits) end}
        end
      else
        {"crypto:hash", fn -> :crypto.hash(algorithm, input) end}
      end
    end
  end

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
