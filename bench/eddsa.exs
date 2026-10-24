# Run from the repository root:
#   gmake && elixir bench/eddsa.exs
#   BENCH_BYTES=65536 BENCH_TIME=10 elixir bench/eddsa.exs

Mix.install([{:benchee, "~> 1.5.1"}])
Code.require_file("support/grouped_console.exs", __DIR__)

Code.prepend_path(Path.expand("../ebin", __DIR__))
{:ok, _} = :libdecaf.start()

bytes = System.get_env("BENCH_BYTES", "1024") |> String.to_integer()
time = System.get_env("BENCH_TIME", "5") |> String.to_integer()

if bytes < 0 or time < 1,
  do: raise("BENCH_BYTES must be nonnegative and BENCH_TIME must be positive")

message = :binary.copy(<<0>>, bytes)

jobs =
  for {curve, seed_bytes} <- [{:ed25519, 32}, {:ed448, 57}], reduce: %{} do
    jobs ->
      # Prepare matching keys and signatures outside the timed operations.
      seed = :crypto.strong_rand_bytes(seed_bytes)
      {public, ^seed} = :crypto.generate_key(:eddsa, curve, seed)
      keypair = :libdecaf.eddsa_keypair(curve, seed)
      {^public, ^seed} = :libdecaf.eddsa_keypair_extract(keypair)

      signature = :crypto.sign(:eddsa, :none, message, [seed, curve])
      ^signature = :libdecaf.eddsa_sign({curve, seed}, message)
      ^signature = :libdecaf.eddsa_sign({curve, keypair}, message)
      true = :crypto.verify(:eddsa, :none, message, signature, [public, curve])
      true = :libdecaf.eddsa_verify({curve, public}, signature, message)

      Map.merge(jobs, %{
        "#{curve} / keypair from seed / crypto" => fn ->
          :crypto.generate_key(:eddsa, curve, seed)
        end,
        "#{curve} / keypair from seed / libdecaf" => fn ->
          :libdecaf.eddsa_keypair(curve, seed)
        end,
        "#{curve} / sign (seed) / crypto" => fn ->
          :crypto.sign(:eddsa, :none, message, [seed, curve])
        end,
        "#{curve} / sign (seed) / libdecaf" => fn ->
          :libdecaf.eddsa_sign({curve, seed}, message)
        end,
        # Reusing libdecaf's opaque keypair avoids deriving it on every signature.
        "#{curve} / sign (cached keypair) / libdecaf" => fn ->
          :libdecaf.eddsa_sign({curve, keypair}, message)
        end,
        "#{curve} / verify / crypto" => fn ->
          :crypto.verify(:eddsa, :none, message, signature, [public, curve])
        end,
        "#{curve} / verify / libdecaf" => fn ->
          :libdecaf.eddsa_verify({curve, public}, signature, message)
        end
      })
  end

IO.puts(
  "EdDSA comparison: #{bytes}-byte messages, one caller, pure Ed25519/Ed448, empty context."
)

IO.puts("Matching public keys, signatures, and successful verification checked before timing.")
IO.inspect(:crypto.info_lib(), label: "crypto backend")

Benchee.run(jobs,
  time: time,
  warmup: 1,
  parallel: 1,
  formatters: [LibdecafBench.GroupedConsole]
)
