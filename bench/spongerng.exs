# gmake && elixir bench/spongerng.exs
# BENCH_SCALE=2 repeats twice as many calls. Warm-cache, single-caller measurements.
Code.prepend_path(Path.expand("../ebin", __DIR__))

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
end

scale = System.get_env("BENCH_SCALE", "1") |> String.to_integer()
if scale < 1, do: raise("BENCH_SCALE must be positive")
LibdecafRandomBench.warmup()
IO.puts("bytes / API                                      ns/call       MiB/s")

for {bytes, count} <- [
      {32, 100_000},
      {256, 100_000},
      {4096, 20_000},
      {65536, 2048},
      {1_048_576, 128}
    ],
    {name, function} <- [
      {"crypto", &:crypto.strong_rand_bytes/1},
      {"libdecaf", &:libdecaf.strong_rand_bytes/1}
    ] do
  LibdecafRandomBench.loop(function, bytes, 100)
  {elapsed, :ok} = :timer.tc(fn -> LibdecafRandomBench.loop(function, bytes, count * scale) end)
  ns = elapsed * 1000 / (count * scale)
  mib = bytes * count * scale / (1024 * 1024) / (elapsed / 1_000_000)
  :io.format("~-45s ~12.2f ~12.2f~n", ["#{bytes} / #{name}", ns, mib])
end
