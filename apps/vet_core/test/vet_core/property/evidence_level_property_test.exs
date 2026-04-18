defmodule VetCore.Property.EvidenceLevelPropertyTest do
  @moduledoc """
  Properties for the clearwing-style evidence-level ladder added to Finding.

  The ladder is: pattern_match → corroborated → sandbox_observed →
  llm_confirmed → known_incident.

  Scoring must be monotone non-decreasing along the ladder for any fixed
  (severity, compile_time?) combination — that's the whole point of the
  ladder. These properties prove it holds across all inputs.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  import VetCore.Generators

  alias VetCore.Scorer
  alias VetCore.Types.Finding

  @moduletag :property

  @ladder [:pattern_match, :corroborated, :sandbox_observed, :llm_confirmed, :known_incident]

  defp base_finding(dep_name, severity, compile_time?, evidence) do
    %Finding{
      dep_name: dep_name,
      file_path: "deps/#{dep_name}/lib/x.ex",
      line: 1,
      check_id: :system_exec,
      category: :system_exec,
      severity: severity,
      compile_time?: compile_time?,
      evidence_level: evidence,
      description: "property test finding"
    }
  end

  property "evidence_weight is monotone non-decreasing along the ladder" do
    check all(
            i <- integer(0..(length(@ladder) - 2)),
            max_runs: 50
          ) do
      lower = Enum.at(@ladder, i)
      upper = Enum.at(@ladder, i + 1)
      assert Scorer.evidence_weight(lower) <= Scorer.evidence_weight(upper)
    end
  end

  property "score is monotone non-decreasing in evidence_level for fixed severity/ct" do
    check all(
            dep <- dependency(),
            sev <- severity(),
            ct? <- boolean(),
            i <- integer(0..(length(@ladder) - 2)),
            max_runs: 200
          ) do
      lower = Enum.at(@ladder, i)
      upper = Enum.at(@ladder, i + 1)

      f_low = base_finding(dep.name, sev, ct?, lower)
      f_high = base_finding(dep.name, sev, ct?, upper)

      {score_low, _} = Scorer.score(dep, [f_low], nil)
      {score_high, _} = Scorer.score(dep, [f_high], nil)

      assert score_low <= score_high
    end
  end

  property "pattern_match is the scoring baseline (weight == 1.0)" do
    assert Scorer.evidence_weight(:pattern_match) == 1.0
  end

  property "unknown evidence_level atoms default to weight 1.0" do
    check all(
            garbage <- member_of([:unknown, :made_up, :foo]),
            max_runs: 10
          ) do
      assert Scorer.evidence_weight(garbage) == 1.0
    end
  end

  property "score stays in [0, 100] regardless of evidence_level" do
    check all({dep, findings, meta} <- scoring_context(), max_runs: 200) do
      {score, level} = Scorer.score(dep, findings, meta)
      assert score >= 0 and score <= 100
      assert level in [:low, :medium, :high, :critical]
    end
  end

  property "permuting findings never changes the total score" do
    check all({dep, findings, meta} <- scoring_context(), max_runs: 100) do
      {s1, _} = Scorer.score(dep, findings, meta)
      {s2, _} = Scorer.score(dep, Enum.reverse(findings), meta)
      assert s1 == s2
    end
  end
end
