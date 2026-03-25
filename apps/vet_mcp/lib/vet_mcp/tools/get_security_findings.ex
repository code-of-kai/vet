defmodule VetMcp.Tools.GetSecurityFindings do
  @moduledoc false
  @behaviour VetMcp.Tool

  @impl true
  def name, do: "vet_scan_dependencies"

  @impl true
  def description do
    "Scan the current project's dependencies for security vulnerabilities and " <>
      "supply chain attack patterns. Returns findings with risk scores, compile-time " <>
      "vs runtime classification, and remediation suggestions."
  end

  @impl true
  def schema do
    %{
      type: "object",
      properties: %{
        path: %{
          type: "string",
          description: "Project path (defaults to current directory)"
        },
        skip_hex: %{
          type: "boolean",
          description: "Skip hex.pm metadata checks"
        },
        threshold: %{
          type: "integer",
          description: "Minimum risk score to report (0-100)"
        }
      }
    }
  end

  @impl true
  def execute(params, _context) do
    path = Map.get(params, "path", File.cwd!())
    skip_hex = Map.get(params, "skip_hex", false)
    threshold = Map.get(params, "threshold", 0)

    case VetCore.scan(path, skip_hex: skip_hex) do
      {:ok, report} ->
        filtered_report = filter_by_threshold(report, threshold)
        {:ok, VetReporter.Json.encode(filtered_report)}

      {:error, reason} ->
        {:error, "Scan failed: #{inspect(reason)}"}
    end
  end

  defp filter_by_threshold(report, 0), do: report

  defp filter_by_threshold(report, threshold) do
    filtered_deps =
      Enum.filter(report.dependency_reports, fn dep_report ->
        dep_report.risk_score >= threshold
      end)

    %{report | dependency_reports: filtered_deps}
  end
end
