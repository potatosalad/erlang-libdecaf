# Run from the repository root:
#   gmake && elixir bench/spongerng.exs
#   BENCH_TIME=1 elixir bench/spongerng.exs
# Default: 0.1 seconds per case, with no per-case warmup.
# BENCH_SCALE multiplies the target measurement time. One caller, warmed schedulers.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.require_file("support/grouped_console.exs", __DIR__)

Code.prepend_path(Path.expand("../ebin", __DIR__))
{:ok, _} = :libdecaf.start()

defmodule LibdecafRandomBench do
  def warmup do
    schedulers = :erlang.system_info(:schedulers_online)
    parent = self()

    workers =
      for scheduler <- 1..schedulers, _ <- 1..4 do
        :erlang.spawn_opt(
          fn ->
            receive do: (:warmup -> :ok)
            ^scheduler = :erlang.system_info(:scheduler_id)
            loop(&:crypto.strong_rand_bytes/1, 32, 128)
            loop(&:libdecaf.strong_rand_bytes/1, 32, 128)
            send(parent, {:warmed, self(), scheduler})
          end,
          [:monitor, {:scheduler, scheduler}]
        )
      end

    Enum.each(workers, fn {pid, _} -> send(pid, :warmup) end)

    Enum.each(workers, fn {pid, monitor} ->
      receive do
        {:warmed, ^pid, _scheduler} ->
          receive do
            {:DOWN, ^monitor, :process, ^pid, :normal} -> :ok
            {:DOWN, ^monitor, :process, ^pid, reason} -> raise "warmup failed: #{inspect(reason)}"
          end

        {:DOWN, ^monitor, :process, ^pid, reason} ->
          raise "warmup failed: #{inspect(reason)}"
      after
        30_000 -> raise "warmup timed out"
      end
    end)

    IO.puts(
      "Warmed both APIs with #{length(workers)} pinned processes across #{schedulers} online schedulers."
    )
  end

  def loop(_function, _bytes, 0), do: :ok

  def loop(function, bytes, count) do
    output = function.(bytes)
    ^bytes = byte_size(output)
    loop(function, bytes, count - 1)
  end

  def report(suite) do
    suite.scenarios
    |> Enum.group_by(& &1.input_name)
    |> Enum.sort_by(fn {_input, [scenario | _]} -> scenario.input end)
    |> Enum.each(fn {_input, scenarios} ->
      group = Benchee.relative_statistics(%{suite | scenarios: scenarios})
      Benchee.Formatter.output(group, Benchee.Formatters.Console)

      rates =
        Enum.map_join(group.scenarios, " | ", fn scenario ->
          rate = scenario.input * scenario.run_time_data.statistics.ips / (1024 * 1024)
          "#{scenario.name}: #{:erlang.float_to_binary(rate, decimals: 2)}"
        end)

      IO.puts("\nThroughput (MiB/s): #{rates}")
    end)
  end
end

scale = System.get_env("BENCH_SCALE", "1") |> String.to_integer()
{time, ""} = System.get_env("BENCH_TIME", "0.1") |> Float.parse()
if scale < 1 or time <= 0, do: raise("BENCH_SCALE and BENCH_TIME must be positive")

sizes = [{"32 B", 32}, {"256 B", 256}, {"4 KiB", 4096}, {"64 KiB", 65536}, {"1 MiB", 1_048_576}]
seed = :crypto.strong_rand_bytes(64)
bulk_seed = :binary.copy(seed, div(1_048_576, byte_size(seed)))

seed_file =
  Path.join(
    System.tmp_dir!(),
    "libdecaf-spongerng-#{System.pid()}-#{System.unique_integer([:positive])}.seed"
  )

File.write!(seed_file, seed, [:exclusive])

try do
  LibdecafRandomBench.warmup()
  state = :libdecaf_spongerng.init_from_buffer(seed, true)
  file_state = :libdecaf_spongerng.init_from_file(seed_file, byte_size(seed), true)
  {_, file_output} = :libdecaf_spongerng.next(file_state, 32)
  32 = byte_size(file_output)

  for {_label, bytes} <- sizes do
    {_, output} = :libdecaf_spongerng.next(state, bytes)
    ^bytes = byte_size(output)
    ^bytes = byte_size(:libdecaf.strong_rand_bytes(bytes))
    ^bytes = byte_size(:crypto.strong_rand_bytes(bytes))
  end

  operations =
    Enum.reduce(
      [{"deterministic", true}, {"nondeterministic", false}],
      %{
        "64 B seed / init_from_dev_urandom / OS entropy" => fn ->
          :libdecaf_spongerng.init_from_dev_urandom()
        end
      },
      fn {mode, deterministic}, jobs ->
        prepared_state = :libdecaf_spongerng.init_from_buffer(seed, deterministic)

        init_and_stir = %{
          "64 B seed / init_from_buffer / #{mode}" => fn ->
            :libdecaf_spongerng.init_from_buffer(seed, deterministic)
          end,
          "64 B seed / init_from_file / #{mode}" => fn ->
            :libdecaf_spongerng.init_from_file(seed_file, byte_size(seed), deterministic)
          end,
          "64 B input / stir / #{mode}" => fn ->
            :libdecaf_spongerng.stir(prepared_state, seed)
          end,
          "1 MiB input / stir / #{mode}" => fn ->
            :libdecaf_spongerng.stir(prepared_state, bulk_seed)
          end
        }

        next =
          Map.new(sizes, fn {label, bytes} ->
            {"#{label} output / next / #{mode}",
             fn -> :libdecaf_spongerng.next(prepared_state, bytes) end}
          end)

        jobs |> Map.merge(init_and_stir) |> Map.merge(next)
      end
    )

  IO.puts("Individual next/stir calls use prepared immutable states; initialization is separate.")
  IO.puts("File initialization includes opening and reading a prepared 64-byte seed file.")

  Benchee.run(operations,
    time: time * scale,
    warmup: 0,
    parallel: 1,
    formatters: [LibdecafBench.GroupedConsole]
  )

  Benchee.run(
    %{
      "libdecaf" => fn bytes -> :libdecaf.strong_rand_bytes(bytes) end,
      "crypto" => fn bytes -> :crypto.strong_rand_bytes(bytes) end
    },
    inputs: Map.new(sizes),
    title: "strong_rand_bytes/1",
    time: time * scale,
    warmup: 0,
    parallel: 1,
    formatters: [&LibdecafRandomBench.report/1]
  )
after
  File.rm!(seed_file)
end
