defmodule VetService.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      VetService.Store
    ]

    opts = [strategy: :one_for_one, name: VetService.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
