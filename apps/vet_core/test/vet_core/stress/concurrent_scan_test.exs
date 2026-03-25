defmodule VetCore.Stress.ConcurrentScanTest do
  use ExUnit.Case, async: false

  alias VetCore.Types.ScanReport

  @moduletag timeout: 60_000

  setup do
    tmp_dir =
      Path.join(
        System.tmp_dir!(),
        "vet_concurrent_stress_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp_dir)

    # Create a small but non-trivial project to scan concurrently
    lock_content = ~s(%{
  "alpha": {:hex, :alpha, "1.0.0", "aaa111", [:mix], [], "hexpm", "bbb222"},
  "beta": {:hex, :beta, "2.0.0", "ccc333", [:mix], [], "hexpm", "ddd444"},
  "gamma": {:hex, :gamma, "3.0.0", "eee555", [:mix], [], "hexpm", "fff666"}
})

    File.write!(Path.join(tmp_dir, "mix.lock"), lock_content)

    for dep_name <- ["alpha", "beta", "gamma"] do
      dep_dir = Path.join([tmp_dir, "deps", dep_name])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      File.write!(
        Path.join(dep_dir, "mix.exs"),
        "defmodule #{String.capitalize(dep_name)}.MixProject do\n  use Mix.Project\n  def project, do: [app: :#{dep_name}, version: \"1.0.0\"]\nend\n"
      )

      File.write!(
        Path.join(lib_dir, "#{dep_name}.ex"),
        "defmodule #{String.capitalize(dep_name)} do\n  def hello, do: System.cmd(\"echo\", [\"hi\"])\nend\n"
      )
    end

    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  describe "10 concurrent scans against the same project" do
    test "all 10 return correct results with no race conditions", %{project_path: project_path} do
      tasks =
        Enum.map(1..10, fn _i ->
          Task.async(fn ->
            VetCore.scan(project_path, skip_hex: true)
          end)
        end)

      results = Task.await_many(tasks, 50_000)

      # All 10 should succeed
      assert length(results) == 10

      for {result, idx} <- Enum.with_index(results, 1) do
        assert {:ok, %ScanReport{} = report} = result,
               "Scan ##{idx} failed: #{inspect(result)}"

        assert length(report.dependency_reports) == 3,
               "Scan ##{idx} returned #{length(report.dependency_reports)} deps, expected 3"

        dep_names =
          report.dependency_reports
          |> Enum.map(fn dr -> dr.dependency.name end)
          |> Enum.sort()

        assert dep_names == [:alpha, :beta, :gamma],
               "Scan ##{idx} dep names mismatch: #{inspect(dep_names)}"

        # Each dep should have at least one system_exec finding
        for dr <- report.dependency_reports do
          system_findings = Enum.filter(dr.findings, &(&1.category == :system_exec))

          assert length(system_findings) > 0,
                 "Scan ##{idx}: #{dr.dependency.name} missing system_exec findings"
        end
      end
    end

    test "Task.Supervisor handles concurrent load without crashing", %{project_path: project_path} do
      # Slightly different test: verify the supervisor itself is alive after concurrent load
      supervisor_pid = Process.whereis(VetCore.ScanSupervisor)
      assert supervisor_pid != nil, "ScanSupervisor should be running"
      assert Process.alive?(supervisor_pid)

      tasks =
        Enum.map(1..10, fn _i ->
          Task.async(fn ->
            VetCore.scan(project_path, skip_hex: true)
          end)
        end)

      Task.await_many(tasks, 50_000)

      # Supervisor should still be alive after all concurrent scans
      assert Process.alive?(supervisor_pid),
             "ScanSupervisor died during concurrent scanning"
    end
  end
end
