import Config

# Configure vet_service database (not used in tests that don't need DB)
config :vet_service, VetService.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "vet_service_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :vet_web, VetWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "test_only_secret_key_base_that_is_at_least_64_bytes_long_for_phoenix_to_accept_it_okk",
  server: false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime
