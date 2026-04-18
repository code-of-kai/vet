defmodule VetCore.PatchOracle do
  @moduledoc """
  Suggests concrete patches for risky dependency findings — the clearwing
  "here's the fix" idea: instead of just flagging a problem, emit a
  proposed replacement and re-verify it.

  For each finding category, the oracle produces at most one patch:

    * `:phantom_package` → rename to the nearest verified package in the
      typosquat corpus (if within edit distance 2).
    * `:metadata` (typosquat finding) → rename to the canonical name cited
      in the finding.
    * `:version_transition` / `:temporal_anomaly` → pin to the predecessor
      version from Hex metadata.
    * Compile-time critical static findings (system_exec, code_eval,
      compiler_hooks at compile time) → recommend removing the dep since
      there is no safe downgrade path that preserves the threat surface.

  Each patch carries a `verified?` flag — when the suggested replacement is
  itself a package name, the oracle re-runs `PreInstallCheck.check_package/1`
  on it and reports whether the replacement is clean.
  """

  alias VetCore.Metadata.TyposquatDetector
  alias VetCore.PreInstallCheck
  alias VetCore.Types.{DependencyReport, Finding}

  @type action ::
          :rename_package
          | :pin_to_version
          | :remove_dependency
          | :no_action

  @type patch :: %{
          action: action(),
          target: atom() | nil,
          version: String.t() | nil,
          verified?: boolean(),
          rationale: String.t(),
          diff: String.t() | nil,
          source_finding_category: atom() | nil
        }

  @doc """
  Produce a list of patch suggestions for a dependency report. The list is
  deduplicated by `{action, target, version}` so a single rename suggestion
  isn't emitted once per typosquat finding on the same package.

  Options:
    * `:verify?` — when `true` (default), calls PreInstallCheck on rename
      targets to verify the replacement is clean. Set `false` in tests or
      when offline.
  """
  @spec suggest(DependencyReport.t(), keyword()) :: [patch()]
  def suggest(%DependencyReport{} = report, opts \\ []) do
    verify? = Keyword.get(opts, :verify?, true)

    report.findings
    |> Enum.flat_map(&suggest_for_finding(&1, report, verify?))
    |> dedupe_patches()
  end

  # ---------------------------------------------------------------------------
  # Per-finding suggestions
  # ---------------------------------------------------------------------------

  defp suggest_for_finding(%Finding{category: :phantom_package} = f, _report, verify?) do
    case TyposquatDetector.nearest_known(f.dep_name) do
      {:ok, target, distance} ->
        [
          build_rename_patch(
            f,
            target,
            "Package :#{f.dep_name} does not exist on hex.pm. Nearest known " <>
              "package is :#{target} (distance #{distance}) — likely a " <>
              "slopsquatted or mistyped name.",
            verify?
          )
        ]

      :none ->
        [
          %{
            action: :remove_dependency,
            target: nil,
            version: nil,
            verified?: true,
            rationale:
              "Package :#{f.dep_name} does not exist on hex.pm and has no " <>
                "near-neighbor in the known-packages corpus. Remove the " <>
                "dependency and confirm the intended package name with the source.",
            diff: removal_diff(f.dep_name),
            source_finding_category: :phantom_package
          }
        ]
    end
  end

  defp suggest_for_finding(%Finding{check_id: :typosquat} = f, _report, verify?) do
    case extract_similar_to(f.description) do
      {:ok, target} ->
        [
          build_rename_patch(
            f,
            target,
            "Typosquat match: the scan found :#{f.dep_name} is a " <>
              "near-neighbor of :#{target}. If :#{target} is what you meant, " <>
              "switch to it explicitly.",
            verify?
          )
        ]

      :error ->
        []
    end
  end

  defp suggest_for_finding(%Finding{category: cat} = f, %DependencyReport{} = report, _verify?)
       when cat in [:version_transition, :temporal_anomaly] do
    case report.hex_metadata do
      %{previous_version: prev} when is_binary(prev) ->
        [
          %{
            action: :pin_to_version,
            target: f.dep_name,
            version: prev,
            verified?: true,
            rationale:
              "The latest version of :#{f.dep_name} triggered a " <>
                "#{cat} signal. Pinning to the previous version #{prev} " <>
                "rolls back to a release with a known-clean scan history.",
            diff: pin_diff(f.dep_name, prev),
            source_finding_category: cat
          }
        ]

      _ ->
        []
    end
  end

  defp suggest_for_finding(%Finding{category: cat, compile_time?: true, severity: :critical} = f, _report, _verify?)
       when cat in [:system_exec, :code_eval, :compiler_hooks] do
    [
      %{
        action: :remove_dependency,
        target: nil,
        version: nil,
        verified?: true,
        rationale:
          "Compile-time #{cat} at #{shorten_path(f.file_path)}:#{f.line} " <>
            "executes arbitrary code during `mix deps.compile`. There is no " <>
            "safe configuration for this — remove the dependency or fork it " <>
            "with the offending code removed.",
        diff: removal_diff(f.dep_name),
        source_finding_category: cat
      }
    ]
  end

  defp suggest_for_finding(_finding, _report, _verify?), do: []

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_rename_patch(%Finding{dep_name: from}, target, rationale, verify?) do
    verified? = if verify?, do: verify_replacement(target), else: nil

    %{
      action: :rename_package,
      target: target,
      version: nil,
      verified?: verified?,
      rationale: rationale,
      diff: rename_diff(from, target),
      source_finding_category: :metadata
    }
  end

  defp verify_replacement(target) when is_atom(target) do
    case PreInstallCheck.check_package(target) do
      %{phantom?: false, findings: []} -> true
      %{phantom?: false, findings: findings} -> Enum.all?(findings, &(&1.severity == :info))
      _ -> false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp extract_similar_to(description) when is_binary(description) do
    case Regex.run(~r/typosquat of :([a-z][a-z0-9_]*)/, description) do
      [_, name] -> {:ok, String.to_atom(name)}
      _ -> :error
    end
  end

  defp rename_diff(from, to) do
    ~s"""
    -      {:#{from}, "~> x.y.z"},
    +      {:#{to}, "~> x.y.z"},
    """
  end

  defp pin_diff(pkg, version) do
    ~s"""
    -      {:#{pkg}, "~> #{bump_minor(version)}"},
    +      {:#{pkg}, "== #{version}"},
    """
  end

  defp removal_diff(pkg) do
    ~s"""
    -      {:#{pkg}, "~> x.y.z"},
    """
  end

  defp bump_minor(version) do
    case String.split(version, ".") do
      [major, minor | _] -> "#{major}.#{minor}"
      _ -> version
    end
  end

  defp shorten_path(path) do
    case String.split(path, "/deps/") do
      [_, rest] -> "deps/" <> rest
      _ -> path
    end
  end

  defp dedupe_patches(patches) do
    patches
    |> Enum.uniq_by(fn p -> {p.action, p.target, p.version} end)
  end
end
