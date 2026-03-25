defmodule VetReporter.Diagnostics do
  @moduledoc false

  alias VetCore.Types.{ScanReport, DependencyReport}

  def render(%ScanReport{} = report) do
    report.dependency_reports
    |> Enum.flat_map(&diagnostics_for_dep/1)
    |> Enum.each(&print_diagnostic/1)
  end

  defp diagnostics_for_dep(%DependencyReport{} = dr) do
    Enum.map(dr.findings, fn finding ->
      %{
        file: finding.file_path,
        position: finding.line,
        severity: map_severity(finding.severity),
        message: "[vet:#{finding.check_id}] #{finding.description}",
        compiler_name: "vet"
      }
    end)
  end

  defp print_diagnostic(diag) do
    prefix =
      case diag.severity do
        :error -> "error"
        :warning -> "warning"
        :information -> "info"
      end

    IO.puts("#{diag.file}:#{diag.position}: #{prefix}: #{diag.message}")
  end

  defp map_severity(:critical), do: :error
  defp map_severity(:warning), do: :warning
  defp map_severity(:info), do: :information
end
