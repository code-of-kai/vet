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
      allowlist_notes = compute_allowlist_notes(deps, dependency_reports)

      report = %ScanReport{
        project_path: project_path,
        timestamp: DateTime.utc_now(),
        dependency_reports: dependency_reports,
        summary: summary,
        allowlist_notes: allowlist_notes
      }

      {:ok, report}
    end
  end

  # -- Private -----------------------------------------------------------------

  defp compute_allowlist_notes(deps, dependency_reports) do
    deps_by_name = Map.new(deps, &{&1.name, &1})
    reports_by_name = Map.new(dependency_reports, &{&1.dependency.name, &1})

    # Find all allowlisted packages (those that have any built-in or user suppressions)
    allowlisted_names =
      deps
      |> Enum.filter(fn dep ->
        VetCore.Allowlist.suppressed?(dep.name, :code_eval) or
          VetCore.Allowlist.suppressed?(dep.name, :system_exec) or
          VetCore.Allowlist.suppressed?(dep.name, :network_access) or
          VetCore.Allowlist.suppressed?(dep.name, :file_access) or
          VetCore.Allowlist.suppressed?(dep.name, :env_access) or
          VetCore.Allowlist.suppressed?(dep.name, :obfuscation) or
          VetCore.Allowlist.suppressed?(dep.name, :compiler_hooks) or
          VetCore.Allowlist.suppressed?(dep.name, :dos_atom_exhaustion) or
          VetCore.Allowlist.suppressed?(dep.name, :shady_links)
      end)
      |> Enum.map(& &1.name)

    # For each allowlisted package, walk its full transitive dep tree
    # and find any deps with unallowlisted findings
    Enum.flat_map(allowlisted_names, fn parent_name ->
      transitive_deps = collect_transitive_deps(parent_name, deps_by_name, MapSet.new())

      transitive_deps
      |> Enum.flat_map(fn dep_name ->
        case Map.get(reports_by_name, dep_name) do
          %{findings: findings} when findings != [] ->
            categories = findings |> Enum.map(& &1.category) |> Enum.uniq()

            [
              %{
                package: parent_name,
                transitive_dep: dep_name,
                finding_count: length(findings),
                categories: categories
              }
            ]

          _ ->
            []
        end
      end)
    end)
    |> Enum.uniq_by(&{&1.package, &1.transitive_dep})
  end

  defp collect_transitive_deps(name, deps_by_name, visited) do
    if name in visited do
      visited
    else
      visited = MapSet.put(visited, name)

      children =
        case Map.get(deps_by_name, name) do
          %{children: children} when is_list(children) -> children
          _ -> []
        end

      Enum.reduce(children, visited, fn child, acc ->
        collect_transitive_deps(child, deps_by_name, acc)
      end)
    end
    |> MapSet.delete(name)
  end

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
