defmodule VetService.Pipeline.ScanPipeline do
  @moduledoc """
  Orchestrates the scan pipeline: parses a publish event,
  runs the deterministic scan, and returns result events.
  """

  alias VetService.CommandHandlers.ScanHandler
  alias VetService.Events.PackageVersionPublished

  @doc """
  Process a raw publish event payload (map or JSON string).

  Returns `{:ok, scan_completed_event}` or `{:error, reason}`.
  """
  @spec process_publish_event(map() | String.t()) :: {:ok, struct()} | {:error, term()}
  def process_publish_event(payload) when is_binary(payload) do
    case Jason.decode(payload) do
      {:ok, decoded} -> process_publish_event(decoded)
      {:error, reason} -> {:error, {:json_decode, reason}}
    end
  end

  def process_publish_event(%{"package_name" => name, "version" => version} = payload) do
    _publish_event = %PackageVersionPublished{
      package_name: name,
      version: version,
      published_at: Map.get(payload, "published_at"),
      hex_metadata: Map.get(payload, "hex_metadata", %{})
    }

    scan_id = generate_scan_id()

    case ScanHandler.handle(name, version, scan_id) do
      [scan_event | _rest] -> {:ok, scan_event}
      [] -> {:error, :no_events_produced}
    end
  end

  def process_publish_event(_payload), do: {:error, :invalid_payload}

  defp generate_scan_id do
    Base.hex_encode32(:crypto.strong_rand_bytes(10), case: :lower, padding: false)
  end
end
