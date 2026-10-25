# Run from the repository root:
#   gmake && elixir bench/ecdh.exs
#   BENCH_TIME=1 elixir bench/ecdh.exs
# Default: 0.1 seconds per case, with no per-case warmup.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.require_file("support/grouped_console.exs", __DIR__)

Code.prepend_path(Path.expand("../ebin", __DIR__))
{:ok, _} = :libdecaf.start()

{time, ""} = System.get_env("BENCH_TIME", "0.1") |> Float.parse()
if time <= 0, do: raise("BENCH_TIME must be positive")

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
  warmup: 0,
  parallel: 1,
  formatters: [LibdecafBench.GroupedConsole]
)
