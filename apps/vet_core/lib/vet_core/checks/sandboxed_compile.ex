defmodule VetCore.Checks.SandboxedCompile do
  @moduledoc """
  Layer 2 — Sandboxed compile observation.

  Compiles a dependency inside an OS sandbox (macOS sandbox-exec, Linux
  bubblewrap) with network denied and writes restricted to the dep's
  workdir. Fires findings based on observed out-of-policy behavior:

  - network attempts (the package's compile phase tried to reach the
    internet)
  - subprocess spawns outside the allow-list
  - writes outside the workdir
  - sandbox-denied syscalls in the audit log

  Compiling untrusted code is fundamentally dangerous — the sandbox is
  the line of defense, not a nice-to-have. This check is OPT-IN via
  `sandboxed_compile: true` in scan opts because compilation is slow
  and sometimes fails for reasons unrelated to safety (missing system
  tools, hex.pm access, env vars).
  """
  use VetCore.Check

  alias VetCore.Sandbox.{BehaviorReport, Runner}
  alias VetCore.Types.Finding

  @category :sandboxed_compile_behavior

  @impl true
  def run(%{name: dep_name} = _dep, project_path, state) do
    if opted_in?(state) do
      dep_dir = Path.join([project_path, "deps", to_string(dep_name)])

      cond do
        not File.dir?(dep_dir) ->
          []

        true ->
          do_run(dep_name, dep_dir)
      end
    else
      []
    end
  end

  # --- Internals -------------------------------------------------------------

  defp opted_in?(state) do
    case state do
      list when is_list(list) -> Keyword.get(list, :sandboxed_compile, false)
      %{sandboxed_compile: true} -> true
      _ -> false
    end
  end

  defp do_run(dep_name, dep_dir) do
    policy = Runner.compile_policy(dep_dir)

    command = [
      System.find_executable("mix") || "mix",
      "deps.compile",
      to_string(dep_name),
      "--force"
    ]

    report = Runner.run(command, dep_dir, policy)
    report_to_findings(report, dep_name)
  end

  @doc """
  Convert a `BehaviorReport` into a list of findings. Exposed for test
  harnesses that bypass the runner.
  """
  @spec report_to_findings(BehaviorReport.t(), atom()) :: [Finding.t()]
  def report_to_findings(%BehaviorReport{sandbox_available?: false}, _dep_name), do: []

  def report_to_findings(%BehaviorReport{} = report, dep_name) do
    findings =
      denied_findings(report, dep_name) ++
        network_findings(report, dep_name) ++
        subprocess_findings(report, dep_name) ++
        write_findings(report, dep_name)

    findings
  end

  defp denied_findings(%BehaviorReport{denied_operations: []}, _), do: []

  defp denied_findings(%BehaviorReport{denied_operations: denials} = report, dep_name) do
    Enum.map(denials, fn denial ->
      %Finding{
        dep_name: dep_name,
        file_path: report.workdir,
        line: 1,
        check_id: :sandboxed_compile_denied,
        category: @category,
        severity: :critical,
        compile_time?: true,
        evidence_level: :sandbox_observed,
        description:
          "Sandboxed compile of #{dep_name} attempted a denied operation: " <>
            "#{denial.op} #{denial.target || ""} — " <>
            "this means the build step tried to do something the sandbox rejected"
      }
    end)
  end

  defp network_findings(%BehaviorReport{network_attempts: []}, _), do: []

  defp network_findings(%BehaviorReport{network_attempts: attempts} = report, dep_name) do
    Enum.map(attempts, fn {host, port} ->
      %Finding{
        dep_name: dep_name,
        file_path: report.workdir,
        line: 1,
        check_id: :sandboxed_compile_network,
        category: @category,
        severity: :critical,
        compile_time?: true,
        evidence_level: :sandbox_observed,
        description:
          "Sandboxed compile of #{dep_name} attempted a network connection to " <>
            "#{host}:#{port} — compile phase should not need the network"
      }
    end)
  end

  defp subprocess_findings(%BehaviorReport{processes_spawned: []}, _), do: []

  defp subprocess_findings(%BehaviorReport{processes_spawned: procs} = report, dep_name) do
    Enum.map(procs, fn exe ->
      %Finding{
        dep_name: dep_name,
        file_path: report.workdir,
        line: 1,
        check_id: :sandboxed_compile_subprocess,
        category: @category,
        severity: :warning,
        compile_time?: true,
        evidence_level: :sandbox_observed,
        description:
          "Sandboxed compile of #{dep_name} spawned subprocess: #{exe}"
      }
    end)
  end

  defp write_findings(%BehaviorReport{files_written: []}, _), do: []

  defp write_findings(%BehaviorReport{files_written: paths} = report, dep_name) do
    workdir = Path.expand(report.workdir)

    paths
    |> Enum.reject(&String.starts_with?(Path.expand(&1), workdir))
    |> Enum.map(fn path ->
      %Finding{
        dep_name: dep_name,
        file_path: path,
        line: 1,
        check_id: :sandboxed_compile_write,
        category: @category,
        severity: :critical,
        compile_time?: true,
        evidence_level: :sandbox_observed,
        description:
          "Sandboxed compile of #{dep_name} wrote outside the workdir: #{path}"
      }
    end)
  end
end
