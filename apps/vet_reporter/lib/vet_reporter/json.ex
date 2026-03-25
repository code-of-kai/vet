defmodule VetReporter.Json do
  @moduledoc false

  alias VetCore.Types.{ScanReport, DependencyReport, Finding, HexMetadata}

  def render(%ScanReport{} = report) do
    report
    |> serialize()
    |> Jason.encode!(pretty: true)
    |> IO.puts()
  end

  def encode(%ScanReport{} = report) do
    report
    |> serialize()
    |> Jason.encode!(pretty: true)
  end

  defp serialize(%ScanReport{} = report) do
    %{
      project_path: report.project_path,
      timestamp: DateTime.to_iso8601(report.timestamp),
      summary: report.summary,
      dependencies:
        Enum.map(report.dependency_reports, &serialize_dep_report/1)
    }
  end

  defp serialize_dep_report(%DependencyReport{} = dr) do
    %{
      name: dr.dependency.name,
      version: dr.dependency.version,
      hash: dr.dependency.hash,
      source: serialize_source(dr.dependency.source),
      direct: dr.dependency.direct?,
      risk_score: dr.risk_score,
      risk_level: dr.risk_level,
      findings: Enum.map(dr.findings, &serialize_finding/1),
      hex_metadata: serialize_hex_metadata(dr.hex_metadata)
    }
  end

  defp serialize_finding(%Finding{} = f) do
    %{
      check_id: f.check_id,
      category: f.category,
      severity: f.severity,
      compile_time: f.compile_time?,
      file_path: f.file_path,
      line: f.line,
      column: f.column,
      description: f.description,
      snippet: f.snippet
    }
  end

  defp serialize_hex_metadata(nil), do: nil

  defp serialize_hex_metadata(%HexMetadata{} = m) do
    %{
      downloads: m.downloads,
      latest_version: m.latest_version,
      latest_release_date: m.latest_release_date && DateTime.to_iso8601(m.latest_release_date),
      owner_count: m.owner_count,
      description: m.description,
      retired: m.retired?
    }
  end

  defp serialize_source(:hex), do: "hex"
  defp serialize_source({:git, url}), do: "git:#{url}"
  defp serialize_source({:path, path}), do: "path:#{path}"
  defp serialize_source(other), do: to_string(other)
end
