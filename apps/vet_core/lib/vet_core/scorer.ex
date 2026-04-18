defmodule VetCore.Scorer do
  @moduledoc false

  alias VetCore.Types.{DependencyReport, Finding, HexMetadata}

  @spec score(VetCore.Types.Dependency.t(), [Finding.t()], HexMetadata.t() | nil) ::
          {non_neg_integer(), DependencyReport.risk_level()}
  def score(dependency, findings, hex_metadata) do
    source_score = score_findings(findings)
    metadata_score = score_metadata(dependency, hex_metadata)
    raw = source_score + metadata_score
    adjusted = apply_popularity_adjustment(raw, hex_metadata)
    capped = min(adjusted, 100)

    {capped, risk_level(capped)}
  end

  @spec score_report([DependencyReport.t()]) :: map()
  def score_report(dependency_reports) do
    total_deps = length(dependency_reports)

    total_findings =
      dependency_reports
      |> Enum.map(fn report -> length(report.findings) end)
      |> Enum.sum()

    deps_by_risk_level =
      dependency_reports
      |> Enum.group_by(& &1.risk_level)
      |> Map.new(fn {level, reports} -> {level, length(reports)} end)

    highest_risk =
      dependency_reports
      |> Enum.max_by(fn report -> report.risk_score end, fn -> nil end)

    critical_deps =
      Enum.filter(dependency_reports, fn report -> report.risk_level == :critical end)

    high_deps =
      Enum.filter(dependency_reports, fn report -> report.risk_level == :high end)

    %{
      total_deps: total_deps,
      total_findings: total_findings,
      deps_by_risk_level: deps_by_risk_level,
      highest_risk_dep: highest_risk && highest_risk.dependency.name,
      highest_risk_score: highest_risk && highest_risk.risk_score,
      critical_count: length(critical_deps),
      high_count: length(high_deps)
    }
  end

  # -- Private -----------------------------------------------------------------

  # Per-(file, category) bucketing: ten File.read! calls in one module are one
  # piece of evidence ("this module does file I/O"), not ten. Score the first
  # finding in each bucket at full weight; remaining duplicates score as :info.
  # This applies only to source files — BEAM/cross-file findings use unique
  # paths (workdir, dep root) so each still scores independently.
  defp score_findings(findings) do
    findings
    |> Enum.group_by(fn f -> {f.file_path, f.category} end)
    |> Enum.reduce(0, fn {_bucket, group}, acc ->
      [primary | rest] = Enum.sort_by(group, &finding_score/1, :desc)
      acc + finding_score(primary) + length(rest)
    end)
  end

  @doc false
  # Evidence weighting — clearwing-style graduated confidence.
  # Pattern match is baseline (1.0); promotions add weight as independent
  # signals agree (correlation, sandbox trace, LLM second-pass, incident corpus).
  # Monotone non-decreasing along the ladder is an invariant (property-tested).
  @spec evidence_weight(Finding.evidence_level()) :: float()
  def evidence_weight(:pattern_match), do: 1.0
  def evidence_weight(:corroborated), do: 1.3
  def evidence_weight(:sandbox_observed), do: 1.5
  def evidence_weight(:llm_confirmed), do: 1.7
  def evidence_weight(:known_incident), do: 2.5
  def evidence_weight(_), do: 1.0

  defp finding_score(%Finding{} = f) do
    base = severity_base(f)
    round(base * evidence_weight(f.evidence_level))
  end

  defp severity_base(%Finding{compile_time?: true, severity: :critical}), do: 40
  defp severity_base(%Finding{compile_time?: true, severity: :warning}), do: 20
  defp severity_base(%Finding{compile_time?: false, severity: :critical}), do: 15
  defp severity_base(%Finding{compile_time?: false, severity: :warning}), do: 5
  defp severity_base(%Finding{severity: :info}), do: 1

  defp score_metadata(_dependency, nil), do: 0

  defp score_metadata(dependency, %HexMetadata{} = meta) do
    source_penalty(dependency) +
      downloads_penalty(meta.downloads) +
      recency_penalty(meta.latest_release_date) +
      owner_penalty(meta.owner_count) +
      description_penalty(meta.description) +
      depth_penalty(dependency)
  end

  defp source_penalty(%{source: {:git, _}}), do: 10
  defp source_penalty(%{source: {:path, _}}), do: 10
  defp source_penalty(_), do: 0

  defp downloads_penalty(nil), do: 0
  defp downloads_penalty(d) when d < 100, do: 20
  defp downloads_penalty(d) when d < 1000, do: 10
  defp downloads_penalty(_), do: 0

  defp recency_penalty(nil), do: 0

  defp recency_penalty(%DateTime{} = release_date) do
    days_ago = DateTime.diff(DateTime.utc_now(), release_date, :day)

    if days_ago < 7 do
      15
    else
      0
    end
  end

  defp owner_penalty(1), do: 5
  defp owner_penalty(_), do: 0

  defp description_penalty(nil), do: 5
  defp description_penalty(""), do: 5
  defp description_penalty(_), do: 0

  defp depth_penalty(%{depth: d}) when d >= 5, do: 10
  defp depth_penalty(%{depth: d}) when d >= 3, do: 5
  defp depth_penalty(_), do: 0

  defp apply_popularity_adjustment(score, nil), do: score

  defp apply_popularity_adjustment(score, %HexMetadata{downloads: downloads})
       when is_integer(downloads) and downloads > 10_000_000 do
    round(score * 0.3)
  end

  defp apply_popularity_adjustment(score, %HexMetadata{downloads: downloads})
       when is_integer(downloads) and downloads > 1_000_000 do
    round(score * 0.5)
  end

  defp apply_popularity_adjustment(score, _meta), do: score

  defp risk_level(score) when score >= 80, do: :critical
  defp risk_level(score) when score >= 50, do: :high
  defp risk_level(score) when score >= 20, do: :medium
  defp risk_level(_score), do: :low
end
