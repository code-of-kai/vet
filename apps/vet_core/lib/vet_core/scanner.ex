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
    VetCore.Checks.AtomExhaustion,
    # Layer 1 — BEAM bytecode analysis. Runs only when compiled artifacts
    # are present. Defeats source-level evasion (defdelegate, .erl, atom
    # aliasing, macro-synthesized calls).
    VetCore.Checks.BeamImports,
    # Layer 5 — Native code surface. Detects NIF binaries, native build
    # systems, and modules importing :erlang.load_nif/2. Native code
    # bypasses every other Vet layer because it is opaque machine code
    # running in the BEAM scheduler.
    VetCore.Checks.NativeCode,
    # Layer 4 — BEAM-level version delta. Compares the current compiled
    # profile against a cached snapshot of an earlier version. Catches
    # security profile shifts (new dangerous imports, new
    # $handle_undefined_function/2, dispatch spikes, suspicious atoms)
    # that were introduced in this release.
    VetCore.Checks.BeamDelta,
    # Layer 3 — Reflection tripwires at the BEAM level. Counts dynamic
    # dispatch instructions and reflection-class imports per module.
    # Defeats source-level evasion via apply/3, String.to_atom, and
    # $handle_undefined_function/2 because all of them surface in the
    # BEAM regardless of how the source was spelled.
    VetCore.Checks.BeamReflection,
    # Layer 7 — Capability declaration verifier. Compares the
    # `:vet_capabilities` list declared in mix.exs against the
    # capabilities actually exercised by the compiled BEAMs. An
    # undeclared capability is a critical finding because it represents
    # behavior the package's author never promised.
    VetCore.Checks.CapabilityVerifier,
    # Layer 6 — Attestation manifest verification. When a package has a
    # signed `*.manifest.json` + `*.sig` stored in `.vet/attestations/`,
    # confirm the signature is by a trusted key and every declared
    # module hash matches the local install. Opt-in via `attestation:
    # :require` or `:strict`; advisory (no findings for unsigned) by
    # default.
    VetCore.Checks.Attestation
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
          max_concurrency: System.schedulers_online(),
          # Generous per-dep timeout: the BEAM-level layers (imports,
          # reflection, delta, capability, attestation) profile every
          # compiled module in the dep's ebin, which can take several
          # seconds for large packages.
          timeout: 60_000
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

      unless opts[:skip_history] do
        VetCore.ScanStore.save(project_path, report)
      end

      {:ok, report}
    end
  end

  # -- Private -----------------------------------------------------------------

  # SandboxedCompile is opt-in because each run does a real mix deps.compile
  # inside an OS-level sandbox — significantly slower than static analysis.
  defp active_checks(opts) do
    if opts[:sandboxed_compile] do
      @checks ++ [VetCore.Checks.SandboxedCompile]
    else
      @checks
    end
  end

  defp check_state(VetCore.Checks.SandboxedCompile, opts) do
    [sandboxed_compile: true, timeout_ms: opts[:sandbox_timeout_ms]]
  end

  defp check_state(_check_mod, _opts), do: []

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
    |> downgrade_mix_task_findings()
  end

  # Findings inside `lib/mix/**` (or compiled `Elixir.Mix.Tasks.*.beam`) are
  # build-time tooling, not runtime code. A Mix task only executes when the
  # developer explicitly invokes `mix <task>`, and the modules are not part of
  # a production release by default. Keep the signal but drop the severity to
  # :info so 50 RT warnings from a code generator (e.g. `phx.gen.auth`) don't
  # dominate the score the way real runtime risk should. CT findings and
  # sensitive-path criticals are preserved.
  defp downgrade_mix_task_findings(findings) do
    Enum.map(findings, fn finding ->
      cond do
        finding.file_path == nil -> finding
        not mix_task_path?(finding.file_path) -> finding
        finding.compile_time? -> finding
        finding.severity == :critical -> finding
        finding.severity == :info -> finding
        true -> %{finding | severity: :info}
      end
    end)
  end

  defp mix_task_path?(path) do
    String.contains?(path, "/lib/mix/") or
      String.contains?(path, "/Elixir.Mix.Tasks.")
  end

  # apply/3 (warning) + network access in the same dependency = likely exfiltration pipeline
  defp elevate_apply_with_network(findings) do
    has_network? = Enum.any?(findings, &(&1.category == :network_access))

    if has_network? do
      Enum.map(findings, fn finding ->
        if finding.check_id == :obfuscation_dynamic_apply do
          %{finding |
            severity: :critical,
            evidence_level: :corroborated,
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
            evidence_level: :corroborated,
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
    # Parse once per dep (clearwing read-once optimization) and share the
    # result with every check. Previously each of the 9 checks re-read and
    # re-parsed the entire dep independently — 9x redundant I/O per dep.
    parsed_files = VetCore.Checks.FileHelper.read_and_parse(dep.name, project_path)
    state = [parsed_files: parsed_files]

    checks = active_checks(opts)

    all_findings =
      checks
      |> Enum.flat_map(fn check_mod ->
        merged_state = Keyword.merge(state, check_state(check_mod, opts))
        check_mod.run(dep, project_path, merged_state)
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
        {step_diff, step_findings} = run_version_diff(dep, meta, project_path)
        lookback_findings = run_lookback_diff(dep, meta, project_path)
        {step_diff, step_findings ++ lookback_findings}
      end

    # Combine: allowlist-filtered findings + version diff findings (unfiltered)
    combined_findings = filtered_findings ++ version_diff_findings

    # Temporal reputation: load scan history, detect anomalies
    temporal_findings =
      if opts[:skip_history] == true do
        []
      else
        build_temporal_findings(dep, combined_findings, project_path)
      end

    combined_findings = combined_findings ++ temporal_findings

    # Promote findings to :known_incident when the dep matches a public
    # advisory entry in the corpus. Top rung of the evidence ladder.
    combined_findings = VetCore.IncidentCorpus.promote(dep, combined_findings)

    {initial_score, _initial_level} = VetCore.Scorer.score(dep, combined_findings, meta)

    # Adversarial LLM verification (gated). Only runs when requested AND the
    # dep scored high enough to be worth the 3x API cost. Refuted findings
    # get demoted one severity tier; confirmed findings get their
    # evidence_level bumped to :llm_confirmed. Re-score after.
    adversarial_threshold = opts[:adversarial_threshold] || 30

    combined_findings =
      if opts[:adversarial] && combined_findings != [] && initial_score >= adversarial_threshold do
        run_adversarial(dep, combined_findings, meta, project_path, opts)
      else
        combined_findings
      end

    {risk_score, risk_level} = VetCore.Scorer.score(dep, combined_findings, meta)

    # Snapshot this dep's compiled profile into the cache so the next
    # scan can run a BEAM-level diff against this version. Best-effort —
    # missing _build is not an error.
    unless opts[:skip_history] == true do
      VetCore.Checks.BeamDelta.snapshot(dep.name, dep.version, project_path)
    end

    base_report = %DependencyReport{
      dependency: dep,
      findings: combined_findings,
      hex_metadata: meta,
      risk_score: risk_score,
      risk_level: risk_level,
      version_diff: version_diff_result
    }

    # Patch oracle — gated off by default because :verify? hits hex.pm.
    # When enabled, emits concrete mix.exs-level suggestions per finding.
    patches =
      if opts[:patches] do
        verify? = Keyword.get(opts, :verify_patches, false)
        VetCore.PatchOracle.suggest(base_report, verify?: verify?)
      else
        []
      end

    %{base_report | patches: patches}
  end

  defp run_adversarial(dep, findings, meta, project_path, opts) do
    stub_report = %DependencyReport{
      dependency: dep,
      findings: findings,
      hex_metadata: meta,
      risk_score: 0,
      risk_level: :low
    }

    review_opts =
      opts
      |> Keyword.take([:api_key, :model, :max_tokens])
      |> Keyword.put(:project_path, project_path)

    case VetCore.LLMReview.review_with_refutation(stub_report, review_opts) do
      {:ok, %{findings: updated}} ->
        updated

      {:error, reason} ->
        Logger.warning("Vet: adversarial review failed for #{dep.name}: #{inspect(reason)} — " <>
                         "keeping original findings")
        findings
    end
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

  # Lookback diff: compare current version against N releases ago.
  # Catches gradual introduction of malicious code across multiple versions
  # where no single step looks suspicious but the aggregate does.
  defp run_lookback_diff(dep, meta, project_path) do
    lookback_version =
      case meta do
        %{lookback_version: v} when is_binary(v) -> v
        _ -> nil
      end

    prev_version =
      case meta do
        %{previous_version: v} when is_binary(v) -> v
        _ -> nil
      end

    # Only run if lookback is different from the immediate predecessor
    # (otherwise we'd duplicate findings)
    if lookback_version && dep.version &&
       lookback_version != dep.version &&
       lookback_version != prev_version do
      case VetCore.VersionDiff.diff(project_path, dep.name, lookback_version, dep.version) do
        {:ok, diff} ->
          {suspicious?, signals} = VetCore.VersionDiff.suspicious_delta?(diff)

          if suspicious? do
            Enum.map(signals, fn signal ->
              %VetCore.Types.Finding{
                dep_name: dep.name,
                file_path: "version_diff_lookback",
                line: 1,
                check_id: :version_lookback,
                category: :version_transition,
                severity: :warning,
                compile_time?: false,
                description:
                  "Lookback #{lookback_version} to #{dep.version} (across multiple releases): #{signal}"
              }
            end)
          else
            []
          end

        {:error, _} ->
          []
      end
    else
      []
    end
  end

  defp build_temporal_findings(dep, current_findings, project_path) do
    history = VetCore.ScanStore.load_history(project_path, dep.name)

    if history == [] do
      []
    else
      reputation = VetCore.TemporalReputation.build(dep.name, history)
      anomaly = VetCore.TemporalReputation.anomaly_score(reputation, current_findings)

      if anomaly > 0 do
        severity =
          cond do
            anomaly >= 30 -> :critical
            anomaly >= 15 -> :warning
            true -> :info
          end

        [
          %VetCore.Types.Finding{
            dep_name: dep.name,
            file_path: "temporal_reputation",
            line: 1,
            check_id: :temporal_anomaly,
            category: :temporal_anomaly,
            severity: severity,
            compile_time?: false,
            description:
              "Temporal anomaly (score: #{anomaly}): " <>
                "package had #{reputation.clean_streak} consecutive clean scans " <>
                "but now has #{length(current_findings)} finding(s) — " <>
                "possible supply chain compromise"
          }
        ]
      else
        []
      end
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
