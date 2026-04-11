defmodule VetCore.Metadata.HexChecker do
  @moduledoc false

  require Logger

  alias VetCore.Types.HexMetadata

  def check(deps) when is_list(deps) do
    deps
    |> Enum.filter(&(&1.source == :hex))
    |> Enum.map(fn dep ->
      case VetCore.Metadata.RateLimiter.throttle(fn ->
             fetch_metadata(dep.name, dep.version)
           end) do
        {:ok, metadata} -> {dep.name, metadata}
        {:error, _reason} -> {dep.name, nil}
      end
    end)
    |> Map.new()
  end

  def fetch_metadata(package_name, current_version \\ nil) do
    case Req.get("https://hex.pm/api/packages/#{package_name}") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, parse_hex_response(body, current_version)}

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
  def parse_hex_response(data, current_version \\ nil) do
    downloads =
      case data do
        %{"downloads" => %{"all" => n}} when is_integer(n) -> n
        _ -> 0
      end

    releases =
      case Map.get(data, "releases") do
        r when is_list(r) -> r
        _ -> []
      end

    latest_release = List.first(releases)
    latest_version = latest_release && Map.get(latest_release, "version")

    effective_version = current_version || latest_version
    previous_version = find_previous_version(releases, effective_version)
    lookback_version = find_lookback_version(releases, effective_version, 10)

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
      previous_version: previous_version,
      lookback_version: lookback_version,
      owner_count: owners_count,
      description: Map.get(data, "meta", %{}) |> Map.get("description"),
      retired?: retired?
    }
  end

  @doc """
  Find the version published immediately before `current_version` in the
  releases list. Releases are sorted newest-first by hex.pm.
  """
  def find_previous_version(releases, nil), do: nil

  def find_previous_version(releases, current_version) when is_list(releases) do
    releases
    |> Enum.map(fn
      %{"version" => v} when is_binary(v) -> v
      _ -> nil
    end)
    |> Enum.reject(&is_nil/1)
    |> find_after(current_version)
  end

  def find_previous_version(_, _), do: nil

  @doc """
  Find the version N releases before `current_version` in the releases list.
  Used for lookback diffing to catch gradual introduction of malicious code
  across multiple small versions.
  """
  def find_lookback_version(releases, nil, _n), do: nil

  def find_lookback_version(releases, current_version, n) when is_list(releases) and n > 0 do
    versions =
      releases
      |> Enum.map(fn
        %{"version" => v} when is_binary(v) -> v
        _ -> nil
      end)
      |> Enum.reject(&is_nil/1)

    case Enum.find_index(versions, &(&1 == current_version)) do
      nil -> nil
      idx ->
        target_idx = idx + n
        if target_idx < length(versions), do: Enum.at(versions, target_idx), else: List.last(versions)
    end
  end

  def find_lookback_version(_, _, _), do: nil

  # Find the element immediately after `target` in the list.
  # Since releases are newest-first, the element after the current
  # version is the previous version.
  defp find_after([], _target), do: nil

  defp find_after([version, next | _rest], target) when version == target, do: next

  defp find_after([_ | rest], target), do: find_after(rest, target)
end
