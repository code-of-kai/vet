defmodule VetCore.Scanner do
  @moduledoc false

  alias VetCore.Types.{DependencyReport, ScanReport}

  @checks [
    VetCore.Checks.SystemExec,
    VetCore.Checks.CodeEval,
    VetCore.Checks.NetworkAccess,
    VetCore.Checks.FileAccess,
    VetCore.Checks.EnvAccess,
    VetCore.Checks.Obfuscation,
    VetCore.Checks.ShadyLinks,
    VetCore.Checks.CompilerHooks
  ]

  @spec scan(String.t(), keyword()) :: {:ok, ScanReport.t()} | {:error, term()}
  def scan(project_path, opts \\ []) do
    with {:ok, deps} <- VetCore.LockParser.parse(project_path) do
      deps = VetCore.TreeBuilder.build(project_path, deps)
      check_states = init_checks()

      hex_metadata =
        if opts[:skip_hex] do
          %{}
        else
          VetCore.Metadata.HexChecker.check(deps)
        end

      dependency_reports =
        VetCore.ScanSupervisor
        |> Task.Supervisor.async_stream_nolink(
          deps,
          fn dep -> run_checks_for_dep(dep, project_path, check_states, hex_metadata, opts) end,
          ordered: true,
          max_concurrency: System.schedulers_online()
        )
        |> Enum.map(fn
          {:ok, report} -> report
          {:exit, reason} -> raise "Check failed: #{inspect(reason)}"
        end)

      summary = VetCore.Scorer.score_report(dependency_reports)

      report = %ScanReport{
        project_path: project_path,
        timestamp: DateTime.utc_now(),
        dependency_reports: dependency_reports,
        summary: summary
      }

      {:ok, report}
    end
  end

  # -- Private -----------------------------------------------------------------

  defp init_checks do
    Enum.map(@checks, fn check_mod ->
      {check_mod, check_mod.init([])}
    end)
  end

  defp run_checks_for_dep(dep, project_path, check_states, hex_metadata, _opts) do
    all_findings =
      check_states
      |> Enum.flat_map(fn {check_mod, state} ->
        check_mod.run(dep, project_path, state)
      end)

    filtered_findings = VetCore.Allowlist.filter_findings(all_findings, dep.name, project_path)

    meta = Map.get(hex_metadata, dep.name)
    {risk_score, risk_level} = VetCore.Scorer.score(dep, filtered_findings, meta)

    %DependencyReport{
      dependency: dep,
      findings: filtered_findings,
      hex_metadata: meta,
      risk_score: risk_score,
      risk_level: risk_level
    }
  end
end
