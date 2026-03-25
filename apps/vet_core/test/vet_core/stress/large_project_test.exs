defmodule VetCore.Stress.LargeProjectTest do
  use ExUnit.Case, async: false

  alias VetCore.Types.ScanReport

  @moduletag timeout: 60_000

  setup do
    tmp_dir =
      Path.join(
        System.tmp_dir!(),
        "vet_large_project_stress_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  defp create_large_project(project_path, dep_count) do
    # Generate mix.lock with dep_count dependencies
    entries =
      Enum.map_join(1..dep_count, ",\n", fn i ->
        ~s(  "dep_#{i}": {:hex, :dep_#{i}, "1.0.0", "hash#{i}", [:mix], [], "hexpm", "ihash#{i}"})
      end)

    lock_content = "%{\n#{entries}\n}\n"
    File.write!(Path.join(project_path, "mix.lock"), lock_content)

    # Create a deps directory with mix.exs and one lib file for each dep
    for i <- 1..dep_count do
      dep_name = "dep_#{i}"
      dep_dir = Path.join([project_path, "deps", dep_name])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      mix_source = """
      defmodule Dep#{i}.MixProject do
        use Mix.Project

        def project do
          [app: :dep_#{i}, version: "1.0.0"]
        end
      end
      """

      File.write!(Path.join(dep_dir, "mix.exs"), mix_source)

      lib_source = """
      defmodule Dep#{i} do
        def hello, do: :world
        def add(a, b), do: a + b
      end
      """

      File.write!(Path.join(lib_dir, "dep_#{i}.ex"), lib_source)
    end
  end

  describe "scanning a project with 100 dependencies" do
    test "completes in under 30 seconds and reports all deps", %{project_path: project_path} do
      create_large_project(project_path, 100)

      process_count_before = length(Process.list())

      {elapsed_us, result} =
        :timer.tc(fn ->
          VetCore.scan(project_path, skip_hex: true)
        end)

      elapsed_seconds = elapsed_us / 1_000_000

      assert {:ok, %ScanReport{} = report} = result
      assert elapsed_seconds < 30, "Scan took #{elapsed_seconds}s, expected < 30s"

      # All 100 deps should appear in the report
      assert length(report.dependency_reports) == 100

      dep_names =
        report.dependency_reports
        |> Enum.map(fn dr -> dr.dependency.name end)
        |> Enum.sort()

      expected_names = Enum.map(1..100, fn i -> :"dep_#{i}" end) |> Enum.sort()
      assert dep_names == expected_names

      # Verify summary is correct
      assert report.summary.total_deps == 100

      # Check for process leaks (allow some slack for GC timing)
      process_count_after = length(Process.list())
      leaked = process_count_after - process_count_before

      assert leaked < 10,
             "Possible process leak: #{leaked} extra processes after scan (before: #{process_count_before}, after: #{process_count_after})"
    end
  end
end
