defmodule VetReporter.Sarif do
  @moduledoc """
  SARIF 2.1.0 output for Vet findings.

  SARIF (Static Analysis Results Interchange Format) is consumed by GitHub
  Code Scanning, VS Code SARIF Viewer, and every mainstream CI/IDE security
  dashboard. Producing it lets Vet integrate with those pipelines without
  custom adapters.

  Each Vet `Finding` becomes a SARIF `result` carrying the check_id as
  `ruleId`, severity mapped to SARIF `level`, and Vet-specific signals
  (evidence_level, compile_time?, risk_score, dep_name) preserved in
  `properties`. `PatchOracle` suggestions become SARIF `fixes`.
  """

  alias VetCore.Types.{DependencyReport, Finding, ScanReport}

  @sarif_version "2.1.0"
  @schema_uri "https://json.schemastore.org/sarif-2.1.0.json"
  @tool_uri "https://github.com/code-of-kai/vet"

  @spec render(ScanReport.t()) :: :ok
  def render(%ScanReport{} = report) do
    report
    |> encode()
    |> IO.puts()
  end

  @spec encode(ScanReport.t()) :: String.t()
  def encode(%ScanReport{} = report) do
    report
    |> build()
    |> Jason.encode!(pretty: true)
  end

  @doc """
  Builds the SARIF document as a plain map. Public so callers can embed
  Vet's SARIF output into larger workflow responses (e.g. multi-tool
  aggregation) without re-encoding to text.
  """
  @spec build(ScanReport.t()) :: map()
  def build(%ScanReport{} = report) do
    findings_by_dep =
      report.dependency_reports
      |> Enum.flat_map(fn dr ->
        Enum.map(dr.findings, fn f -> {dr, f} end)
      end)

    %{
      "$schema" => @schema_uri,
      "version" => @sarif_version,
      "runs" => [
        %{
          "tool" => tool_section(findings_by_dep),
          "invocations" => [
            %{
              "executionSuccessful" => true,
              "startTimeUtc" => DateTime.to_iso8601(report.timestamp),
              "workingDirectory" => %{"uri" => "file://" <> report.project_path}
            }
          ],
          "results" => Enum.map(findings_by_dep, &result/1),
          "properties" => %{
            "summary" => report.summary
          }
        }
      ]
    }
  end

  # ---------------------------------------------------------------------------
  # Tool / rules
  # ---------------------------------------------------------------------------

  defp tool_section(findings_by_dep) do
    rules =
      findings_by_dep
      |> Enum.map(fn {_dr, f} -> f end)
      |> Enum.uniq_by(& &1.check_id)
      |> Enum.map(&rule/1)

    %{
      "driver" => %{
        "name" => "vet",
        "version" => vet_version(),
        "informationUri" => @tool_uri,
        "rules" => rules
      }
    }
  end

  defp rule(%Finding{check_id: id, category: category}) do
    %{
      "id" => Atom.to_string(id),
      "name" => id |> Atom.to_string() |> Macro.camelize(),
      "shortDescription" => %{"text" => "Vet check: #{id}"},
      "fullDescription" => %{"text" => rule_description(id, category)},
      "defaultConfiguration" => %{"level" => "warning"},
      "properties" => %{"category" => Atom.to_string(category)}
    }
  end

  defp rule_description(id, category) do
    "Vet detects #{category} concerns via the #{id} check. " <>
      "See https://github.com/code-of-kai/vet for the full rule catalog."
  end

  # ---------------------------------------------------------------------------
  # Results / locations / fixes
  # ---------------------------------------------------------------------------

  defp result({%DependencyReport{} = dr, %Finding{} = f}) do
    base = %{
      "ruleId" => Atom.to_string(f.check_id),
      "level" => severity_to_level(f.severity),
      "message" => %{"text" => f.description},
      "locations" => [location(f)],
      "properties" => finding_properties(dr, f)
    }

    case fixes_for(dr, f) do
      [] -> base
      fixes -> Map.put(base, "fixes", fixes)
    end
  end

  defp location(%Finding{file_path: path, line: line, column: column}) do
    region = %{"startLine" => max(line, 1)}
    region = if column && column > 0, do: Map.put(region, "startColumn", column), else: region

    %{
      "physicalLocation" => %{
        "artifactLocation" => %{"uri" => to_uri(path)},
        "region" => region
      }
    }
  end

  defp to_uri("mix.lock"), do: "mix.lock"
  defp to_uri("mix.exs"), do: "mix.exs"
  defp to_uri("version_diff"), do: "mix.lock"
  defp to_uri("version_diff_lookback"), do: "mix.lock"
  defp to_uri("temporal_reputation"), do: "mix.lock"

  defp to_uri(path) do
    case String.split(path, "/deps/", parts: 2) do
      [_, rest] -> "deps/" <> rest
      _ -> path
    end
  end

  defp finding_properties(%DependencyReport{} = dr, %Finding{} = f) do
    %{
      "dep_name" => Atom.to_string(f.dep_name),
      "dep_version" => dr.dependency.version,
      "category" => Atom.to_string(f.category),
      "evidence_level" => Atom.to_string(f.evidence_level),
      "compile_time" => f.compile_time?,
      "risk_score" => dr.risk_score,
      "risk_level" => Atom.to_string(dr.risk_level),
      "snippet" => f.snippet
    }
    |> reject_nil()
  end

  defp fixes_for(%DependencyReport{patches: patches}, %Finding{category: finding_cat}) do
    patches
    |> Enum.filter(fn p -> relevant_patch?(p, finding_cat) end)
    |> Enum.map(&fix/1)
  end

  # A patch is "relevant" to a finding when its source category matches, or
  # the patch is a remove_dependency (which applies to any finding on the
  # same dep). Rename patches only attach to typosquat/phantom findings.
  defp relevant_patch?(%{action: :remove_dependency}, _category), do: true
  defp relevant_patch?(%{action: :rename_package}, category) when category in [:metadata, :phantom_package], do: true

  defp relevant_patch?(%{source_finding_category: patch_cat}, finding_cat),
    do: patch_cat == finding_cat

  defp relevant_patch?(_patch, _category), do: false

  defp fix(%{} = patch) do
    %{
      "description" => %{"text" => patch.rationale},
      "properties" =>
        %{
          "action" => Atom.to_string(patch.action),
          "target" => patch.target && Atom.to_string(patch.target),
          "version" => patch.version,
          "verified" => patch.verified?,
          "diff" => patch.diff
        }
        |> reject_nil()
    }
  end

  # ---------------------------------------------------------------------------
  # Mapping helpers
  # ---------------------------------------------------------------------------

  # SARIF levels: none | note | warning | error.
  defp severity_to_level(:critical), do: "error"
  defp severity_to_level(:warning), do: "warning"
  defp severity_to_level(:info), do: "note"
  defp severity_to_level(_), do: "warning"

  defp reject_nil(map) do
    :maps.filter(fn _k, v -> not is_nil(v) end, map)
  end

  defp vet_version do
    case Application.spec(:vet_reporter, :vsn) do
      nil -> "0.0.0"
      vsn -> List.to_string(vsn)
    end
  end
end
