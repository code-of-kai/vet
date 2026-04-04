defmodule VetCore.Metadata.HexChecker do
  @moduledoc false

  require Logger

  alias VetCore.Types.HexMetadata

  def check(deps) when is_list(deps) do
    deps
    |> Enum.filter(&(&1.source == :hex))
    |> Enum.map(fn dep ->
      case VetCore.Metadata.RateLimiter.throttle(fn -> fetch_metadata(dep.name) end) do
        {:ok, metadata} -> {dep.name, metadata}
        {:error, _reason} -> {dep.name, nil}
      end
    end)
    |> Map.new()
  end

  def fetch_metadata(package_name) do
    case Req.get("https://hex.pm/api/packages/#{package_name}") do
      {:ok, %{status: 200, body: body}} ->
        # body is already decoded JSON (Req auto-decodes)
        {:ok, parse_hex_response(body)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status}} ->
        Logger.warning("Hex API returned #{status} for #{package_name}")
        {:error, "Hex API returned #{status} for #{package_name}"}

      {:error, reason} ->
        Logger.warning("Hex API request failed for #{package_name}: #{inspect(reason)}")
        {:error, "Hex API request failed: #{inspect(reason)}"}
    end
  end

  @doc false
  def parse_hex_response(data) do
    downloads = get_in(data, ["downloads", "all"]) || 0

    latest_release =
      case Map.get(data, "releases") do
        releases when is_list(releases) -> List.first(releases)
        _ -> nil
      end

    latest_version = latest_release && Map.get(latest_release, "version")

    latest_release_date =
      with %{"inserted_at" => date_str} <- latest_release,
           {:ok, dt, _} <- DateTime.from_iso8601(date_str) do
        dt
      else
        _ -> nil
      end

    owners_count =
      case Map.get(data, "owners") do
        owners when is_list(owners) -> length(owners)
        _ -> nil
      end

    retired? =
      case latest_release do
        %{"retirement" => %{}} -> true
        _ -> false
      end

    %HexMetadata{
      downloads: downloads,
      latest_version: latest_version,
      latest_release_date: latest_release_date,
      owner_count: owners_count,
      description: Map.get(data, "meta", %{}) |> Map.get("description"),
      retired?: retired?
    }
  end
end
