defmodule VetCore.Metadata.HexChecker do
  @moduledoc false

  alias VetCore.Types.HexMetadata

  @hex_api_url ~c"https://hex.pm/api/packages/"

  def check(deps) when is_list(deps) do
    deps
    |> Enum.filter(&(&1.source == :hex))
    |> Enum.map(fn dep ->
      metadata = VetCore.Metadata.RateLimiter.throttle(fn -> fetch_metadata(dep.name) end)
      {dep.name, metadata}
    end)
    |> Map.new()
  end

  def fetch_metadata(package_name) do
    url = @hex_api_url ++ to_charlist(package_name)

    case :httpc.request(:get, {url, [{~c"user-agent", ~c"vet/0.1.0"}]}, [{:ssl, ssl_opts()}], []) do
      {:ok, {{_, 200, _}, _headers, body}} ->
        parse_response(body)

      {:ok, {{_, 404, _}, _, _}} ->
        %HexMetadata{}

      {:error, _reason} ->
        %HexMetadata{}
    end
  end

  defp parse_response(body) do
    case Jason.decode(to_string(body)) do
      {:ok, data} ->
        downloads = get_in(data, ["downloads", "all"]) || 0

        latest_release =
          data
          |> Map.get("releases", [])
          |> List.first()

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

      {:error, _} ->
        %HexMetadata{}
    end
  end

  defp ssl_opts do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      depth: 3,
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ]
    ]
  end
end
