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

  # Cross-check: when individually-weak signals appear together, they become strong.
  defp correlate_findings(findings) do
    findings
    |> elevate_apply_with_network()
    |> elevate_entropy_with_crypto()
  end

  # apply/3 (warning) + network access in the same dependency = likely exfiltration pipeline
  defp elevate_apply_with_network(findings) do
    has_network? = Enum.any?(findings, &(&1.category == :network_access))

    if has_network? do
      Enum.map(findings, fn finding ->
        if finding.check_id == :obfuscation_dynamic_apply do
          %{finding |
            severity: :critical,
            description: finding.description <>
              " (ELEVATED: combined with network access in the same dependency — likely exfiltration pipeline)"
          }
        else
          finding
        end
      end)
    else
      findings
    end
  end

  # High-entropy string + crypto decryption calls = possible encrypted malicious payload
  defp elevate_entropy_with_crypto(findings) do
    has_entropy? = Enum.any?(findings, &(&1.check_id == :obfuscation_entropy))
    has_crypto? = Enum.any?(findings, &(&1.check_id == :obfuscation_crypto_decrypt))

    if has_entropy? and has_crypto? do
      Enum.map(findings, fn finding ->
        if finding.check_id in [:obfuscation_entropy, :obfuscation_crypto_decrypt] do
          %{finding |
            severity: :critical,
            description: finding.description <>
              " (ELEVATED: high-entropy payload paired with decryption capability — possible encrypted malicious code)"
          }
        else
          finding
        end
      end)
    else
      findings
    end
  end

  defp run_checks_for_dep(dep, project_path, hex_metadata, opts) do
    all_findings =
      @checks
      |> Enum.flat_map(fn check_mod ->
        check_mod.run(dep, project_path, [])
      end)
      |> correlate_findings()

    filtered_findings = VetCore.Allowlist.filter_findings(all_findings, dep.name, project_path)

    meta = Map.get(hex_metadata, dep.name)

    # Version diff: compare current version against predecessor.
    # These findings BYPASS the allowlist — they represent version
    # transition threats, not static patterns. The allowlist says
    # "we trust what this package has always done." A version diff
    # says "something changed."
    {version_diff_result, version_diff_findings} =
      if opts[:skip_diff] == true or dep.source != :hex do
        {nil, []}
      else
        run_version_diff(dep, meta, project_path)
      end

    # Combine: allowlist-filtered findings + version diff findings (unfiltered)
    combined_findings = filtered_findings ++ version_diff_findings

    {risk_score, risk_level} = VetCore.Scorer.score(dep, combined_findings, meta)

    %DependencyReport{
      dependency: dep,
      findings: combined_findings,
      hex_metadata: meta,
      risk_score: risk_score,
      risk_level: risk_level,
      version_diff: version_diff_result
    }
  end

  defp run_version_diff(dep, meta, project_path) do
    prev_version =
      case meta do
        %{previous_version: v} when is_binary(v) -> v
        _ -> nil
      end

    if prev_version && dep.version && prev_version != dep.version do
      case VetCore.VersionDiff.diff(project_path, dep.name, prev_version, dep.version) do
        {:ok, diff} ->
          {suspicious?, signals} = VetCore.VersionDiff.suspicious_delta?(diff)
          findings = version_diff_findings(dep.name, prev_version, dep.version, suspicious?, signals)
          {diff, findings}

        {:error, _} ->
          {nil, []}
      end
    else
      {nil, []}
    end
  end

  defp version_diff_findings(_dep_name, _prev, _curr, false, _signals), do: []

  defp version_diff_findings(dep_name, prev_version, curr_version, true, signals) do
    Enum.map(signals, fn signal ->
      {severity, description} =
        case signal do
          :profile_shift ->
            {:critical,
             "Version transition #{prev_version} → #{curr_version}: security profile shift detected — " <>
               "new categories of dangerous patterns appeared in this version"}

          :unexpected_new_files ->
            {:warning,
             "Version transition #{prev_version} → #{curr_version}: unexpected new non-test files added"}

          :findings_increased ->
            {:warning,
             "Version transition #{prev_version} → #{curr_version}: security findings increased " <>
               "(more dangerous patterns than previous version)"}

          other ->
            {:warning,
             "Version transition #{prev_version} → #{curr_version}: #{other}"}
        end

      %VetCore.Types.Finding{
        dep_name: dep_name,
        file_path: "version_diff",
        line: 1,
        check_id: :version_transition,
        category: :version_transition,
        severity: severity,
        compile_time?: false,
        description: description
      }
    end)
  end
end
