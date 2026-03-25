defmodule VetService.Repo do
  use Ecto.Repo,
    otp_app: :vet_service,
    adapter: Ecto.Adapters.Postgres
end
