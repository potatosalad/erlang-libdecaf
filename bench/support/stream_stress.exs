Code.prepend_path(Path.expand("../../ebin", __DIR__))
{:ok, _} = :libdecaf.start()

defmodule LibdecafBench.StreamStress do
  @key :binary.copy(<<0>>, 32)
  @customization :binary.copy(<<0>>, 32)
  @parallel_algorithms [
    :hopmac128,
    :hopmac256,
    :kt128,
    :kt256,
    :parallelhash128,
    :parallelhash256,
    :parallelhashxof128,
    :parallelhashxof256
  ]

  def run(api) do
    gib = System.get_env("BENCH_GIB", "4") |> String.to_integer()
    default_mib = if api in [:parallel_hash, :parallel_xof], do: "32", else: "4"
    mib = System.get_env("BENCH_MIB", default_mib) |> String.to_integer()
    rounds = System.get_env("BENCH_ROUNDS", "0") |> String.to_integer()
    callers = System.get_env("BENCH_CALLERS", "1") |> String.to_integer()

    if gib < 1 or mib < 1 or rounds < 0 or callers < 1,
      do:
        raise(
          "BENCH_GIB, BENCH_MIB, and BENCH_CALLERS must be positive; BENCH_ROUNDS may be zero"
        )

    if rem(gib * 1024, mib) != 0,
      do: raise("BENCH_MIB must divide BENCH_GIB * 1024 exactly")

    :ok = :application.set_env(:libdecaf, :parallel_absorb_rounds, rounds)
    chunk = :binary.copy(<<0>>, mib * 1024 * 1024)
    updates = div(gib * 1024, mib)
    cases = cases(api)
    validate(cases)

    IO.puts(
      "#{length(cases)} cases; one #{gib} GiB pass per case per caller, in #{mib} MiB chunks."
    )

    IO.puts("Input storage is reused; initialization, absorption, and final output are timed.")
    IO.puts("Small-input streaming checks passed against the regular one-shot APIs.")

    IO.puts(
      "Parallel worker budget: #{rounds} leaves (0 drains until idle); callers: #{callers}."
    )

    IO.puts("ParallelHash blocks are 8 KiB; TupleHash treats each chunk as one tuple element.")

    jobs =
      Map.new(cases, fn {name, implementation, parameters, output_bytes} ->
        {name, fn -> stream(implementation, parameters, chunk, updates, output_bytes) end}
      end)

    Benchee.run(jobs,
      # The first invocation is retained as a sample; the cap prevents another pass.
      time: 1,
      max_sample_size: 1,
      warmup: 0,
      pre_check: false,
      parallel: callers,
      print: [configuration: false],
      formatters: [fn suite -> report(suite, gib, cases) end]
    )
  end

  def cases(api) do
    {kind, implementations} =
      case api do
        :hash -> {:hash, [:hash, :parallel_hash]}
        :xof -> {:xof, [:xof, :parallel_xof]}
        :parallel_hash -> {:hash, [:parallel_hash]}
        :parallel_xof -> {:xof, [:parallel_xof]}
      end

    for {parameters, output_bytes} <- parameters(kind),
        implementation <- implementations,
        algorithm = algorithm(parameters),
        implementation == kind or algorithm in @parallel_algorithms do
      {"#{algorithm} / #{implementation}", implementation, parameters, output_bytes}
    end
  end

  defp parameters(:hash) do
    [
      {:sha2_512, 64},
      {:sha3_224, 28},
      {:sha3_256, 32},
      {:sha3_384, 48},
      {:sha3_512, 64},
      {:keccak_224, 28},
      {:keccak_256, 32},
      {:keccak_384, 48},
      {:keccak_512, 64},
      {{:shake128, 32}, 32},
      {{:shake256, 64}, 64},
      {{:keccakxof_128, 32}, 32},
      {{:keccakxof_256, 64}, 64},
      {{:cshake128, 32, "libdecaf benchmark", @customization}, 32},
      {{:cshake256, 64, "libdecaf benchmark", @customization}, 64},
      {{:turboshake128, 32}, 32},
      {{:turboshake256, 64}, 64},
      {{:kt128, 32}, 32},
      {{:kt256, 64}, 64},
      {{:kmac128, 32, @key, @customization}, 32},
      {{:kmac256, 64, @key, @customization}, 64},
      {{:hopmac128, 32, @key, @customization}, 32},
      {{:hopmac256, 64, @key, @customization}, 64},
      {{:parallelhash128, 32, 8192}, 32},
      {{:parallelhash256, 64, 8192}, 64},
      {{:tuplehash128, 32, @customization}, 32},
      {{:tuplehash256, 64, @customization}, 64}
    ]
  end

  defp parameters(:xof) do
    [
      {:shake128, 32},
      {:shake256, 64},
      {:keccakxof_128, 32},
      {:keccakxof_256, 64},
      {{:cshake128, "libdecaf benchmark", @customization}, 32},
      {{:cshake256, "libdecaf benchmark", @customization}, 64},
      {:turboshake128, 32},
      {:turboshake256, 64},
      {:kt128, 32},
      {:kt256, 64},
      {{:kmacxof128, @key, @customization}, 32},
      {{:kmacxof256, @key, @customization}, 64},
      {{:hopmac128, @key, @customization}, 32},
      {{:hopmac256, @key, @customization}, 64},
      {{:parallelhashxof128, 8192}, 32},
      {{:parallelhashxof256, 8192}, 64},
      {{:tuplehashxof128, @customization}, 32},
      {{:tuplehashxof256, @customization}, 64}
    ]
  end

  defp algorithm(parameters) when is_tuple(parameters), do: elem(parameters, 0)
  defp algorithm(parameters), do: parameters

  defp validate(cases) do
    # Cross a leaf boundary and perform two updates, including TupleHash framing.
    chunk = :binary.copy(<<0>>, 8193)

    for {_name, api, parameters, output_bytes} <- cases do
      expected =
        if api in [:hash, :parallel_hash],
          do: :libdecaf.hash(parameters, [chunk, chunk]),
          else: :libdecaf.xof(parameters, [chunk, chunk], output_bytes)

      ^expected = stream(api, parameters, chunk, 2, output_bytes)
      ^output_bytes = byte_size(expected)
    end
  end

  defp stream(api, parameters, chunk, updates, output_bytes) do
    state =
      case api do
        :hash -> :libdecaf.hash_init(parameters)
        :parallel_hash -> :libdecaf.parallel_hash_init(parameters)
        :xof -> :libdecaf.xof_init(parameters)
        :parallel_xof -> :libdecaf.parallel_xof_init(parameters)
      end

    absorb(api, state, chunk, updates, output_bytes)
  end

  defp absorb(:hash, state, _chunk, 0, _length), do: :libdecaf.hash_final(state)
  defp absorb(:parallel_hash, state, _chunk, 0, _length), do: :libdecaf.parallel_hash_final(state)

  defp absorb(:xof, state, _chunk, 0, length) do
    {_state, output} = :libdecaf.xof_squeeze(state, length)
    output
  end

  defp absorb(:parallel_xof, state, _chunk, 0, length) do
    {_state, output} = :libdecaf.parallel_xof_squeeze(state, length)
    output
  end

  defp absorb(:hash, state, chunk, remaining, length),
    do: absorb(:hash, :libdecaf.hash_update(state, chunk), chunk, remaining - 1, length)

  defp absorb(:parallel_hash, state, chunk, remaining, length),
    do:
      absorb(
        :parallel_hash,
        :libdecaf.parallel_hash_update(state, chunk),
        chunk,
        remaining - 1,
        length
      )

  defp absorb(:xof, state, chunk, remaining, length),
    do: absorb(:xof, :libdecaf.xof_absorb(state, chunk), chunk, remaining - 1, length)

  defp absorb(:parallel_xof, state, chunk, remaining, length),
    do:
      absorb(
        :parallel_xof,
        :libdecaf.parallel_xof_absorb(state, chunk),
        chunk,
        remaining - 1,
        length
      )

  defp report(suite, gib, cases) do
    output_sizes = Map.new(cases, fn {name, _api, _parameters, bytes} -> {name, bytes} end)
    IO.puts("\nCompleted-message throughput (MiB/s per caller; fastest first):")

    IO.puts(
      :io_lib.format("~-38s ~12s ~10s ~8s ~8s ~10s", [
        "Algorithm / API",
        "MiB/s",
        "Seconds",
        "Output B",
        "Passes",
        "Total GiB"
      ])
    )

    for scenario <- suite.scenarios do
      stats = scenario.run_time_data.statistics

      IO.puts(
        :io_lib.format("~-38s ~12.2f ~10.3f ~8B ~8B ~10B", [
          scenario.name,
          gib * 1024 * stats.ips,
          stats.average / 1_000_000_000,
          Map.fetch!(output_sizes, scenario.name),
          stats.sample_size,
          stats.sample_size * gib
        ])
      )
    end
  end
end
