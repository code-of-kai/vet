defmodule VetCore.PreInstallCheck do
  @moduledoc """
  Pre-install dependency verification. Checks package names against hex.pm
  and the typosquat corpus BEFORE dependencies are fetched.

  Detects two attack vectors:
  - Typosquatting: names within edit-distance-1 of popular packages
  - Slopsquatting: hallucinated package names registered by attackers
    (detected as phantom packages — 404 on hex.pm or very low adoption
    combined with proximity to a real package name)
  """

  alias VetCore.Metadata.{HexChecker, TyposquatDetector}
  alias VetCore.TreeBuilder
  alias VetCore.Types.{Dependency, Finding}

  @package_name_re ~r/\A[a-z][a-z0-9_]{0,63}\z/

  @doc """
  Validate a package name string and convert to atom.
  Bounded input validation prevents atom table exhaustion.
  """
  def validate_package_name(name) when is_binary(name) do
    if Regex.match?(@package_name_re, name) do
      {:ok, String.to_atom(name)}
    else
      {:error, "Invalid package name: must match [a-z][a-z0-9_]{0,63}"}
    end
  end

  @doc """
  Check a single package by atom name.
  Returns a result map with metadata, typosquat warnings, phantom status, and assessment.
  """
  def check_package(package_atom) when is_atom(package_atom) do
    dep = %Dependency{name: package_atom, source: :hex}

    {hex_result, typosquat_findings} = {
      HexChecker.fetch_metadata(package_atom),
      TyposquatDetector.check_dep(dep)
    }

    {metadata, phantom?} =
      case hex_result do
        {:ok, meta} -> {meta, false}
        {:error, :not_found} -> {nil, true}
        {:error, _} -> {nil, false}
      end

    phantom_findings =
      if phantom? do
        [
          %Finding{
            dep_name: package_atom,
            file_path: "mix.exs",
            line: 1,
            check_id: :phantom_package,
            category: :phantom_package,
            severity: :critical,
            description: "Package :#{package_atom} does not exist on hex.pm — possible slopsquatting target"
          }
        ]
      else
        []
      end

    all_findings = phantom_findings ++ typosquat_findings

    %{
      package: package_atom,
      metadata: metadata,
      phantom?: phantom?,
      typosquat_warnings: Enum.map(typosquat_findings, & &1.description),
      findings: all_findings,
      assessment: assess(metadata, phantom?, typosquat_findings)
    }
  end

  @doc """
  Check all dependencies declared in a project's mix.exs.
  Does NOT require mix.lock or fetched deps — reads mix.exs directly.
  Returns only packages that have warnings.
  """
  def check_deps(project_path) do
    mix_exs_path = Path.join(project_path, "mix.exs")

    case File.read(mix_exs_path) do
      {:ok, contents} ->
        dep_names = TreeBuilder.extract_dep_names(contents)

        results =
          dep_names
          |> Enum.map(fn name ->
            result = check_package(name)
            Process.sleep(100)
            result
          end)
          |> Enum.filter(fn result ->
            result.phantom? or result.typosquat_warnings != [] or has_metadata_warnings?(result.metadata)
          end)

        {:ok, results}

      {:error, reason} ->
        {:error, "Could not read mix.exs: #{inspect(reason)}"}
    end
  end

  defp has_metadata_warnings?(nil), do: false

  defp has_metadata_warnings?(metadata) do
    (metadata.downloads != nil and metadata.downloads < 1000) or
      metadata.owner_count == 1 or
      metadata.retired? or
      recent_release?(metadata.latest_release_date)
  end

  defp recent_release?(%DateTime{} = dt) do
    DateTime.diff(DateTime.utc_now(), dt, :day) < 7
  end

  defp recent_release?(_), do: false

  defp assess(_metadata, true = _phantom?, typosquat_findings) do
    base = "CRITICAL: Package does not exist on hex.pm."

    if typosquat_findings != [] do
      similar = typosquat_findings |> Enum.map(& &1.description) |> Enum.join("; ")
      base <> " Also similar to known packages: #{similar}. Likely slopsquatting target."
    else
      base <> " Verify the package name is correct before installing."
    end
  end

  defp assess(metadata, false, typosquat_findings) do
    warnings = []

    warnings =
      if metadata && metadata.downloads && metadata.downloads < 1000,
        do: ["Low download count (#{metadata.downloads})" | warnings],
        else: warnings

    warnings =
      if metadata && metadata.owner_count == 1,
        do: ["Single package owner" | warnings],
        else: warnings

    warnings =
      if metadata && metadata.retired?,
        do: ["Package is retired" | warnings],
        else: warnings

    warnings =
      if metadata && metadata.description in [nil, ""],
        do: ["No package description" | warnings],
        else: warnings

    warnings =
      if typosquat_findings != [],
        do: ["Possible typosquat" | warnings],
        else: warnings

    warnings =
      case metadata && metadata.latest_release_date do
        %DateTime{} = dt ->
          days_ago = DateTime.diff(DateTime.utc_now(), dt, :day)

          if days_ago < 7,
            do: ["Latest version published #{days_ago} days ago" | warnings],
            else: warnings

        _ ->
          warnings
      end

    case length(warnings) do
      0 -> "No concerns identified."
      _ -> "Warnings: " <> Enum.join(warnings, "; ")
    end
  end
end
