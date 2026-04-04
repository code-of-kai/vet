defmodule VetWeb.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      VetWeb.Telemetry,
      {Phoenix.PubSub, name: VetWeb.PubSub},
      VetWeb.Endpoint
    ]

    opts = [strategy: :one_for_one, name: VetWeb.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @impl true
  def config_change(changed, _new, removed) do
    VetWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
