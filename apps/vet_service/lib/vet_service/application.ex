defmodule VetService.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      []
      |> maybe_add_repo()
      |> maybe_add_commanded()
      |> maybe_add_broadway()

    opts = [strategy: :one_for_one, name: VetService.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp maybe_add_repo(children) do
    if Application.get_env(:vet_service, :start_repo, false) do
      children ++ [VetService.Repo]
    else
      children
    end
  end

  defp maybe_add_commanded(children) do
    if Application.get_env(:vet_service, VetService.CommandedApp) do
      children ++ [VetService.CommandedApp]
    else
      children
    end
  end

  defp maybe_add_broadway(children) do
    if Application.get_env(:vet_service, :start_broadway, false) do
      children ++ [VetService.Pipeline.HexPublishConsumer]
    else
      children
    end
  end
end
