# Run from the repository root:
#   gmake && elixir bench/ecdh.exs
#   BENCH_TIME=10 elixir bench/ecdh.exs

Mix.install([{:benchee, "~> 1.5.1"}])

Code.prepend_path(Path.expand("../ebin", __DIR__))
{:ok, _} = :libdecaf.start()

time = System.get_env("BENCH_TIME", "5") |> String.to_integer()
if time < 1, do: raise("BENCH_TIME must be positive")

jobs =
  for {curve, scalar_bytes} <- [{:x25519, 32}, {:x448, 56}], reduce: %{} do
    jobs ->
      # Prepare matching local and peer keys outside the timed operations.
      secret = :crypto.strong_rand_bytes(scalar_bytes)
      peer_secret = :crypto.strong_rand_bytes(scalar_bytes)
      # OTP calls X25519/X448 operations :eddh; :ecdh also accepts them as aliases.
      {public, ^secret} = :crypto.generate_key(:eddh, curve, secret)
      {peer_public, ^peer_secret} = :crypto.generate_key(:eddh, curve, peer_secret)
      keypair = :libdecaf.ecdh_keypair(curve, secret)
      peer_keypair = :libdecaf.ecdh_keypair(curve, peer_secret)
      {^public, ^secret} = :libdecaf.ecdh_keypair_extract(keypair)
      {^peer_public, ^peer_secret} = :libdecaf.ecdh_keypair_extract(peer_keypair)

      shared = :crypto.compute_key(:eddh, peer_public, secret, curve)
      ^scalar_bytes = byte_size(shared)
      ^shared = :crypto.compute_key(:eddh, public, peer_secret, curve)
      ^shared = :libdecaf.ecdh_shared_secret(curve, secret, peer_public)
      ^shared = :libdecaf.ecdh_shared_secret(curve, peer_secret, public)
      ^shared = :libdecaf.ecdh_shared_secret(curve, keypair, peer_keypair)
      ^shared = :libdecaf.ecdh_shared_secret(curve, peer_keypair, keypair)

      Map.merge(jobs, %{
        "#{curve} / keypair from scalar / crypto" => fn ->
          :crypto.generate_key(:eddh, curve, secret)
        end,
        "#{curve} / keypair from scalar / libdecaf" => fn ->
          :libdecaf.ecdh_keypair(curve, secret)
        end,
        "#{curve} / shared secret (keys) / crypto" => fn ->
          :crypto.compute_key(:eddh, peer_public, secret, curve)
        end,
        "#{curve} / shared secret (keys) / libdecaf" => fn ->
          :libdecaf.ecdh_shared_secret(curve, secret, peer_public)
        end,
        # Keypair inputs wrap the key bytes; every call still computes the shared secret.
        "#{curve} / shared secret (keypairs) / libdecaf" => fn ->
          :libdecaf.ecdh_shared_secret(curve, keypair, peer_keypair)
        end
      })
  end

IO.puts("ECDH comparison: X25519/X448, one caller, pre-generated secret scalars.")
IO.puts("Matching public keys and shared secrets in both directions checked before timing.")
IO.inspect(:crypto.info_lib(), label: "crypto backend")

Benchee.run(jobs,
  time: time,
  warmup: 1,
  parallel: 1,
  formatters: [
    fn suite ->
      IO.puts("\nECDH operations (higher ops/s is faster):")

      IO.puts(
        :io_lib.format("~-48s ~12s ~12s ~10s", [
          "Operation / library",
          "ops/s",
          "us/op",
          "Samples"
        ])
      )

      for scenario <- Enum.sort_by(suite.scenarios, & &1.name) do
        stats = scenario.run_time_data.statistics

        IO.puts(
          :io_lib.format("~-48s ~12.2f ~12.2f ~10B", [
            scenario.name,
            stats.ips,
            stats.average / 1000,
            stats.sample_size
          ])
        )
      end
    end
  ]
)
