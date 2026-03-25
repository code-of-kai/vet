defmodule VetCore.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Task.Supervisor, name: VetCore.ScanSupervisor},
      {VetCore.Metadata.RateLimiter, []}
    ]

    opts = [strategy: :one_for_one, name: VetCore.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
