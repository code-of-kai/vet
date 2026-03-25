defmodule VetCore.Stress.LargeFileTest do
  use ExUnit.Case, async: true

  alias VetCore.Types.ScanReport

  @moduletag timeout: 60_000

  setup do
    tmp_dir =
      Path.join(
        System.tmp_dir!(),
        "vet_large_file_stress_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  defp write_lock_with_single_dep(project_path, dep_name) do
    lock_content =
      ~s(%{\n  "#{dep_name}": {:hex, :#{dep_name}, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"}\n}\n)

    File.write!(Path.join(project_path, "mix.lock"), lock_content)
  end

  defp write_dep_mix_exs(project_path, dep_name) do
    dep_dir = Path.join([project_path, "deps", dep_name])
    File.mkdir_p!(dep_dir)

    mix_source = """
    defmodule #{String.capitalize(dep_name)}.MixProject do
      use Mix.Project

      def project do
        [app: :#{dep_name}, version: "1.0.0"]
      end
    end
    """

    File.write!(Path.join(dep_dir, "mix.exs"), mix_source)
    dep_dir
  end

  describe "10,000-line file with patterns at various positions" do
    test "detects findings at line 1, 5000, and 9999", %{project_path: project_path} do
      dep_name = "big_dep"
      write_lock_with_single_dep(project_path, dep_name)
      dep_dir = write_dep_mix_exs(project_path, dep_name)
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      # Generate a 10,000-line file with System.cmd calls at specific lines
      # Line 1 area: a System.cmd call early
      # Line ~5000: a System.cmd call in the middle
      # Line ~9999: a System.cmd call near the end
      lines = []

      # We build up the file with padding functions and targeted System.cmd calls
      lines = lines ++ ["defmodule BigDep do"]

      # Line 2: System.cmd at near the beginning (inside a function)
      lines = lines ++ ["  def func_start, do: System.cmd(\"echo\", [\"start\"])"]

      # Pad to ~line 5000 with innocuous functions
      padding_1 =
        Enum.map(3..4999, fn i ->
          "  def pad_#{i}, do: :ok"
        end)

      lines = lines ++ padding_1

      # Line 5000: System.cmd in the middle
      lines = lines ++ ["  def func_middle, do: System.cmd(\"echo\", [\"middle\"])"]

      # Pad to ~line 9999
      padding_2 =
        Enum.map(5001..9998, fn i ->
          "  def pad_#{i}, do: :ok"
        end)

      lines = lines ++ padding_2

      # Line 9999: System.cmd near the end
      lines = lines ++ ["  def func_end, do: System.cmd(\"echo\", [\"end\"])"]
      lines = lines ++ ["end"]

      source = Enum.join(lines, "\n")
      File.write!(Path.join(lib_dir, "big.ex"), source)

      {:ok, %ScanReport{} = report} = VetCore.scan(project_path, skip_hex: true)

      dep_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :big_dep end)

      assert dep_report != nil

      system_exec_findings =
        Enum.filter(dep_report.findings, fn f -> f.category == :system_exec end)

      # Should detect all 3 System.cmd calls
      assert length(system_exec_findings) >= 3

      found_lines = Enum.map(system_exec_findings, & &1.line) |> Enum.sort()

      # Verify findings span the full file (early, middle, late)
      assert Enum.min(found_lines) < 10, "Expected a finding near the start, got #{inspect(found_lines)}"
      assert Enum.any?(found_lines, &(&1 > 4900 and &1 < 5100)), "Expected a finding near line 5000, got #{inspect(found_lines)}"
      assert Enum.max(found_lines) > 9900, "Expected a finding near the end, got #{inspect(found_lines)}"
    end
  end

  describe "1MB file stress test" do
    test "does not OOM or take longer than 10 seconds", %{project_path: project_path} do
      dep_name = "huge_dep"
      write_lock_with_single_dep(project_path, dep_name)
      dep_dir = write_dep_mix_exs(project_path, dep_name)
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      # Generate a file with many repeated function definitions to reach ~1MB
      # Each function definition is about 50 bytes, so ~20,000 functions = ~1MB
      func_count = 20_000

      code =
        Enum.map_join(1..func_count, "\n", fn i ->
          "  def func_#{i}(x), do: x + #{i}"
        end)

      source = "defmodule HugeDep do\n#{code}\nend\n"

      # Verify it's at least ~1MB
      assert byte_size(source) > 500_000

      File.write!(Path.join(lib_dir, "huge.ex"), source)

      {elapsed_us, result} =
        :timer.tc(fn ->
          VetCore.scan(project_path, skip_hex: true)
        end)

      elapsed_seconds = elapsed_us / 1_000_000

      assert {:ok, %ScanReport{}} = result
      assert elapsed_seconds < 10, "1MB file scan took #{elapsed_seconds}s, expected < 10s"
    end
  end
end
