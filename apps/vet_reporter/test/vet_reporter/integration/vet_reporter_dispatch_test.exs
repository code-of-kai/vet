defmodule VetReporter.Integration.VetReporterDispatchTest do
  @moduledoc """
  Integration tests for the public `VetReporter.report/2` dispatcher.

  Each format clause must route to the correct renderer and produce the
  shape that format promises. Missing a clause — or silently reformatting
  one to another's output — would be invisible to every upstream consumer
  until they tried to parse it. These tests pin each format's surface.
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias VetCore.Types.{Dependency, DependencyReport, Finding, ScanReport}

  defp sample_report do
    dep = %Dependency{
      name: :risky_dep,
      version: "0.1.0",
      hash: "abc123",
      source: :hex,
      depth: 1,
      direct?: true,
      children: []
    }

    finding = %Finding{
      dep_name: :risky_dep,
      file_path: "deps/risky_dep/lib/risky.ex",
      line: 2,
      column: 1,
      check_id: :system_exec_compile_time,
      category: :system_exec,
      severity: :critical,
      snippet: "System.cmd(...)",
      description: "Compile-time system command execution",
      compile_time?: true,
      evidence_level: :corroborated
    }

    dep_report = %DependencyReport{
      dependency: dep,
      findings: [finding],
      hex_metadata: nil,
      risk_score: 72,
      risk_level: :high,
      version_diff: nil,
      patches: []
    }

    %ScanReport{
      project_path: "/tmp/vet_dispatch_test",
      timestamp: DateTime.from_naive!(~N[2026-04-18 12:00:00], "Etc/UTC"),
      dependency_reports: [dep_report],
      allowlist_notes: [],
      summary: %{total_deps: 1, total_findings: 1}
    }
  end

  defp empty_report do
    %ScanReport{
      project_path: "/tmp/vet_empty",
      timestamp: DateTime.from_naive!(~N[2026-04-18 12:00:00], "Etc/UTC"),
      dependency_reports: [],
      allowlist_notes: [],
      summary: %{total_deps: 0, total_findings: 0}
    }
  end

  describe "report/2 — :terminal" do
    test "writes the ANSI-decorated Vet header" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :terminal) end)

      assert output =~ "Vet — Dependency Security Scan"
    end

    test "prints the project path" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :terminal) end)

      assert output =~ "/tmp/vet_dispatch_test"
    end

    test "prints the dep name and risk score" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :terminal) end)

      assert output =~ "risky_dep"
      assert output =~ "72"
    end

    test "handles an empty report without crashing" do
      output = capture_io(fn -> VetReporter.report(empty_report(), :terminal) end)

      assert output =~ "Vet — Dependency Security Scan"
    end
  end

  describe "report/2 — :json" do
    test "writes a valid pretty-printed JSON document" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :json) end)

      assert {:ok, decoded} = Jason.decode(output)
      assert decoded["project_path"] == "/tmp/vet_dispatch_test"
      assert is_list(decoded["dependencies"])
      assert length(decoded["dependencies"]) == 1
    end

    test "includes findings under each dependency" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :json) end)

      {:ok, decoded} = Jason.decode(output)
      [dep] = decoded["dependencies"]
      assert dep["name"] == "risky_dep"
      assert length(dep["findings"]) == 1
    end

    test "does not emit SARIF markers" do
      # Catches a hypothetical regression where :json fell through to :sarif.
      output = capture_io(fn -> VetReporter.report(sample_report(), :json) end)

      refute output =~ "2.1.0"
      refute output =~ "\"runs\""
    end

    test "empty report is still valid JSON" do
      output = capture_io(fn -> VetReporter.report(empty_report(), :json) end)

      assert {:ok, decoded} = Jason.decode(output)
      assert decoded["dependencies"] == []
    end
  end

  describe "report/2 — :sarif" do
    test "writes a valid SARIF 2.1.0 document" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :sarif) end)

      assert {:ok, decoded} = Jason.decode(output)
      assert decoded["version"] == "2.1.0"
      assert is_list(decoded["runs"])
    end

    test "exactly one run, with tool/driver/results/invocations" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :sarif) end)

      {:ok, decoded} = Jason.decode(output)
      [run] = decoded["runs"]

      assert is_map(run["tool"]["driver"])
      assert is_list(run["results"])
      assert is_list(run["invocations"])
    end

    test "every finding becomes a SARIF result with a rule entry" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :sarif) end)

      {:ok, decoded} = Jason.decode(output)
      [run] = decoded["runs"]

      assert length(run["results"]) == 1
      rule_ids = run["tool"]["driver"]["rules"] |> Enum.map(& &1["id"]) |> MapSet.new()
      [result] = run["results"]
      assert MapSet.member?(rule_ids, result["ruleId"])
    end

    test "does not emit the terminal header" do
      # Catches regression where :sarif fell through to :terminal.
      output = capture_io(fn -> VetReporter.report(sample_report(), :sarif) end)

      refute output =~ "Vet — Dependency Security Scan"
    end

    test "empty report produces well-formed SARIF with zero results" do
      output = capture_io(fn -> VetReporter.report(empty_report(), :sarif) end)

      assert {:ok, decoded} = Jason.decode(output)
      [run] = decoded["runs"]
      assert run["results"] == []
      assert run["tool"]["driver"]["rules"] == []
    end
  end

  describe "report/2 — :diagnostics" do
    test "emits `file:line: severity: [vet:check_id] description` lines" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :diagnostics) end)

      assert output =~
               "deps/risky_dep/lib/risky.ex:2: error: [vet:system_exec_compile_time] Compile-time system command execution"
    end

    test "empty report produces no output" do
      output = capture_io(fn -> VetReporter.report(empty_report(), :diagnostics) end)

      assert output == ""
    end

    test "does not emit JSON punctuation" do
      output = capture_io(fn -> VetReporter.report(sample_report(), :diagnostics) end)

      refute String.starts_with?(output, "{")
      refute output =~ "\"runs\""
    end
  end

  describe "report/1 default format" do
    test "defaults to :terminal when format is omitted" do
      terminal = capture_io(fn -> VetReporter.report(sample_report(), :terminal) end)
      default = capture_io(fn -> VetReporter.report(sample_report()) end)

      assert default == terminal
    end

    test "default on an empty report still emits the Vet header" do
      output = capture_io(fn -> VetReporter.report(empty_report()) end)

      assert output =~ "Vet — Dependency Security Scan"
    end
  end

  describe "format isolation — each format produces a distinct surface" do
    test "sarif, json, terminal, diagnostics all produce different outputs" do
      report = sample_report()

      sarif = capture_io(fn -> VetReporter.report(report, :sarif) end)
      json = capture_io(fn -> VetReporter.report(report, :json) end)
      terminal = capture_io(fn -> VetReporter.report(report, :terminal) end)
      diagnostics = capture_io(fn -> VetReporter.report(report, :diagnostics) end)

      outputs = [sarif, json, terminal, diagnostics]
      assert length(Enum.uniq(outputs)) == 4,
             "expected 4 distinct outputs, got: #{inspect(Enum.map(outputs, &String.slice(&1, 0, 40)))}"
    end

    test "only :sarif produces a `2.1.0` version string" do
      report = sample_report()

      assert capture_io(fn -> VetReporter.report(report, :sarif) end) =~ "2.1.0"
      refute capture_io(fn -> VetReporter.report(report, :json) end) =~ "2.1.0"
      refute capture_io(fn -> VetReporter.report(report, :terminal) end) =~ "2.1.0"
      refute capture_io(fn -> VetReporter.report(report, :diagnostics) end) =~ "2.1.0"
    end

    test "only :json and :sarif produce parseable top-level JSON" do
      report = sample_report()

      assert {:ok, _} =
               capture_io(fn -> VetReporter.report(report, :json) end) |> Jason.decode()

      assert {:ok, _} =
               capture_io(fn -> VetReporter.report(report, :sarif) end) |> Jason.decode()

      assert {:error, _} =
               capture_io(fn -> VetReporter.report(report, :terminal) end) |> Jason.decode()

      # :diagnostics on an empty report prints nothing, which IS valid JSON (null);
      # use a populated report to be sure.
      assert {:error, _} =
               capture_io(fn -> VetReporter.report(report, :diagnostics) end) |> Jason.decode()
    end
  end
end
