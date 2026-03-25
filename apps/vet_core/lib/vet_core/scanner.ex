defmodule VetCore.Scanner do
  @moduledoc false

  require Logger

  alias VetCore.Types.{DependencyReport, ScanReport}

  @checks [
    VetCore.Checks.SystemExec,
    VetCore.Checks.CodeEval,
    VetCore.Checks.NetworkAccess,
    VetCore.Checks.FileAccess,
    VetCore.Checks.EnvAccess,
    VetCore.Checks.Obfuscation,
    VetCore.Checks.ShadyLinks,
    VetCore.Checks.CompilerHooks,
    VetCore.Checks.EExEval,
    VetCore.Checks.AtomExhaustion
  ]

  @spec scan(String.t(), keyword()) :: {:ok, ScanReport.t()} | {:error, term()}
  def scan(project_path, opts \\ []) do
    with {:ok, lock_deps} <- VetCore.LockParser.parse(project_path),
         {:ok, deps} <- VetCore.TreeBuilder.build(project_path, lock_deps) do
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
          fn dep -> run_checks_for_dep(dep, project_path, hex_metadata, opts) end,
          ordered: true,
          max_concurrency: System.schedulers_online()
        )
        |> Enum.zip(deps)
        |> Enum.map(fn
          {{:ok, report}, _dep} ->
            report

          {{:exit, reason}, dep} ->
            Logger.warning("Check failed for #{dep.name}: #{inspect(reason)}")

            %DependencyReport{
              dependency: dep,
              findings: [],
              hex_metadata: Map.get(hex_metadata, dep.name),
              risk_score: 0,
              risk_level: :low
            }
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

  defp run_checks_for_dep(dep, project_path, hex_metadata, _opts) do
    all_findings =
      @checks
      |> Enum.flat_map(fn check_mod ->
        check_mod.run(dep, project_path, [])
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
