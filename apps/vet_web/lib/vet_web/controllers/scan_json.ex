defmodule VetWeb.ScanJSON do
  def show(%{scan: scan}) do
    %{data: data(scan)}
  end

  defp data(scan) do
    base = %{
      id: scan.id,
      project_path: scan.project_path,
      status: scan.status,
      started_at: scan.started_at,
      findings_count: scan.findings_count
    }

    base
    |> maybe_put(:completed_at, Map.get(scan, :completed_at))
    |> maybe_put(:findings, Map.get(scan, :findings))
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
