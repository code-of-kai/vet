defmodule VetCore.ScanStoreTest do
  use ExUnit.Case

  alias VetCore.ScanStore
  alias VetCore.Types.{DependencyReport, Dependency, Finding}

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_scan_store_test_#{:erlang.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir}
  end

  defp make_report(name, version, findings \\ [], risk_score \\ 0) do
    %DependencyReport{
      dependency: %Dependency{name: name, version: version, source: :hex},
      findings: findings,
      risk_score: risk_score,
      risk_level: :low
    }
  end

  defp make_finding(name, category) do
    %Finding{
      dep_name: name,
      file_path: "test.ex",
      line: 1,
      check_id: :test,
      category: category,
      severity: :warning,
      compile_time?: false,
      description: "test finding"
    }
  end

  test "save creates .vet/scans/ directory and writes JSON", %{tmp_dir: tmp_dir} do
    report = %{dependency_reports: [make_report(:phoenix, "1.7.14")]}
    assert :ok = ScanStore.save(tmp_dir, report)

    file = Path.join([tmp_dir, ".vet", "scans", "phoenix.json"])
    assert File.exists?(file)

    {:ok, contents} = File.read(file)
    {:ok, data} = Jason.decode(contents)
    assert length(data) == 1
    assert hd(data)["version"] == "1.7.14"
  end

  test "save appends new versions without duplicating", %{tmp_dir: tmp_dir} do
    report1 = %{dependency_reports: [make_report(:phoenix, "1.7.14")]}
    report2 = %{dependency_reports: [make_report(:phoenix, "1.7.15")]}
    report3 = %{dependency_reports: [make_report(:phoenix, "1.7.14", [], 10)]}

    ScanStore.save(tmp_dir, report1)
    ScanStore.save(tmp_dir, report2)
    # Re-scan same version — should update, not duplicate
    ScanStore.save(tmp_dir, report3)

    history = ScanStore.load_history(tmp_dir, :phoenix)
    assert length(history) == 2
    assert Enum.any?(history, &(&1.version == "1.7.14"))
    assert Enum.any?(history, &(&1.version == "1.7.15"))

    # Updated record should have new risk_score
    updated = Enum.find(history, &(&1.version == "1.7.14"))
    assert updated.risk_score == 10
  end

  test "save persists finding categories", %{tmp_dir: tmp_dir} do
    findings = [
      make_finding(:phoenix, :system_exec),
      make_finding(:phoenix, :network_access),
      make_finding(:phoenix, :system_exec)
    ]

    report = %{dependency_reports: [make_report(:phoenix, "1.7.14", findings, 45)]}
    ScanStore.save(tmp_dir, report)

    [record] = ScanStore.load_history(tmp_dir, :phoenix)
    assert :system_exec in record.categories
    assert :network_access in record.categories
    assert length(record.categories) == 2
    assert record.finding_count == 3
  end

  test "load_history returns empty list for unknown package", %{tmp_dir: tmp_dir} do
    assert [] = ScanStore.load_history(tmp_dir, :nonexistent)
  end

  test "load_all returns all packages", %{tmp_dir: tmp_dir} do
    report = %{
      dependency_reports: [
        make_report(:phoenix, "1.7.14"),
        make_report(:jason, "1.4.0"),
        make_report(:ecto, "3.10.0")
      ]
    }

    ScanStore.save(tmp_dir, report)

    all = ScanStore.load_all(tmp_dir)
    assert Map.has_key?(all, :phoenix)
    assert Map.has_key?(all, :jason)
    assert Map.has_key?(all, :ecto)
    assert length(all[:phoenix]) == 1
  end

  test "load_all returns empty map when no scans dir exists", %{tmp_dir: tmp_dir} do
    assert %{} = ScanStore.load_all(tmp_dir)
  end

  test "load_history returns valid DateTime in scan_date", %{tmp_dir: tmp_dir} do
    report = %{dependency_reports: [make_report(:phoenix, "1.7.14")]}
    ScanStore.save(tmp_dir, report)

    [record] = ScanStore.load_history(tmp_dir, :phoenix)
    assert %DateTime{} = record.scan_date
  end
end
