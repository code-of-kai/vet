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
    result = Supervisor.start_link(children, opts)

    # Register Vet MCP tools with Tidewave after the endpoint (and Tidewave plug) has started
    if Mix.env() == :dev do
      case VetMcp.register() do
        :ok -> IO.puts("[Vet] Registered 3 MCP tools with Tidewave")
        {:error, reason} -> IO.puts("[Vet] Tidewave registration skipped: #{inspect(reason)}")
      end
    end

    result
  end

  @impl true
  def config_change(changed, _new, removed) do
    VetWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
