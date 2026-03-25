import Config

# Ecto Repo — not configured by default so Application.start
# skips it when no database is available.
#
# To enable locally:
#
#   config :vet_service, VetService.Repo,
#     database: "vet_service_dev",
#     username: "postgres",
#     password: "postgres",
#     hostname: "localhost",
#     pool_size: 10
#
# config :vet_service, VetService.CommandedApp, []
# config :vet_service, :start_broadway, true
