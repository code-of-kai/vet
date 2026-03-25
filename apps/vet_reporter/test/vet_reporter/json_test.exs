defmodule VetReporter.JsonTest do
  use ExUnit.Case

  alias VetReporter.Json
  alias VetCore.Types.{ScanReport, DependencyReport, Dependency, Finding, HexMetadata}

  defp make_report(opts \\ []) do
    dep = %Dependency{
      name: :test_dep,
      version: "1.0.0",
      hash: "abc123",
      source: Keyword.get(opts, :source, :hex),
      direct?: true
    }

    findings = Keyword.get(opts, :findings, [
      %Finding{
        dep_name: :test_dep,
        file_path: "lib/test.ex",
        line: 10,
        column: 5,
        check_id: :system_exec,
        category: :system_exec,
        severity: :critical,
        compile_time?: true,
        snippet: "System.cmd(\"curl\", [])",
        description: "System.cmd call"
      }
    ])

    hex_metadata = Keyword.get(opts, :hex_metadata, %HexMetadata{
      downloads: 100_000,
      latest_version: "1.0.0",
      latest_release_date: ~U[2025-01-15 12:00:00Z],
      owner_count: 2,
      description: "A test package",
      retired?: false
    })

    dep_report = %DependencyReport{
      dependency: dep,
      findings: findings,
      hex_metadata: hex_metadata,
      risk_score: 45,
      risk_level: :medium
    }

    %ScanReport{
      project_path: "/tmp/test_project",
      timestamp: ~U[2025-03-01 10:00:00Z],
      summary: %{total_deps: 1, high_risk: 0, critical_risk: 0},
      dependency_reports: [dep_report]
    }
  end

  test "encode/1 returns valid JSON string" do
    report = make_report()

    json_string = Json.encode(report)

    assert is_binary(json_string)
    assert {:ok, _decoded} = Jason.decode(json_string)
  end

  test "serializes all fields correctly" do
    report = make_report()

    json_string = Json.encode(report)
    {:ok, decoded} = Jason.decode(json_string)

    assert decoded["project_path"] == "/tmp/test_project"
    assert decoded["timestamp"] == "2025-03-01T10:00:00Z"
    assert is_map(decoded["summary"])

    [dep_report] = decoded["dependencies"]
    assert dep_report["name"] == "test_dep"
    assert dep_report["version"] == "1.0.0"
    assert dep_report["hash"] == "abc123"
    assert dep_report["source"] == "hex"
    assert dep_report["direct"] == true
    assert dep_report["risk_score"] == 45
    assert dep_report["risk_level"] == "medium"

    [finding] = dep_report["findings"]
    assert finding["check_id"] == "system_exec"
    assert finding["category"] == "system_exec"
    assert finding["severity"] == "critical"
    assert finding["compile_time"] == true
    assert finding["line"] == 10
    assert finding["column"] == 5
    assert finding["description"] == "System.cmd call"

    hex = dep_report["hex_metadata"]
    assert hex["downloads"] == 100_000
    assert hex["latest_version"] == "1.0.0"
    assert hex["owner_count"] == 2
    assert hex["retired"] == false
  end

  test "handles nil hex_metadata" do
    report = make_report(hex_metadata: nil)

    json_string = Json.encode(report)
    {:ok, decoded} = Jason.decode(json_string)

    [dep_report] = decoded["dependencies"]
    assert dep_report["hex_metadata"] == nil
  end

  test "handles :hex source type" do
    report = make_report(source: :hex)

    json_string = Json.encode(report)
    {:ok, decoded} = Jason.decode(json_string)

    [dep_report] = decoded["dependencies"]
    assert dep_report["source"] == "hex"
  end

  test "handles {:git, url} source type" do
    report = make_report(source: {:git, "https://github.com/user/repo.git"})

    json_string = Json.encode(report)
    {:ok, decoded} = Jason.decode(json_string)

    [dep_report] = decoded["dependencies"]
    assert dep_report["source"] == "git:https://github.com/user/repo.git"
  end

  test "handles empty findings" do
    report = make_report(findings: [])

    json_string = Json.encode(report)
    {:ok, decoded} = Jason.decode(json_string)

    [dep_report] = decoded["dependencies"]
    assert dep_report["findings"] == []
  end
end
