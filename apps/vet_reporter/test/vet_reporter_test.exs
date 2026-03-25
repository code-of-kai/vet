defmodule VetReporterTest do
  use ExUnit.Case

  test "report/2 dispatches to terminal format" do
    report = %VetCore.Types.ScanReport{
      project_path: "/tmp/test",
      timestamp: DateTime.utc_now(),
      dependency_reports: [],
      summary: %{total_deps: 0, total_findings: 0}
    }

    assert :ok = VetReporter.report(report, :terminal)
  end
end
