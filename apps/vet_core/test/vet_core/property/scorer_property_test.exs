defmodule VetCore.Property.ScorerPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import VetCore.Generators

  alias VetCore.Scorer

  @moduletag :property

  property "invariant: score is always between 0 and 100" do
    check all({dep, findings, meta} <- scoring_context(), max_runs: 200) do
      {score, _level} = Scorer.score(dep, findings, meta)
      assert score >= 0 and score <= 100
    end
  end

  property "invariant: risk level is consistent with score thresholds" do
    check all({dep, findings, meta} <- scoring_context(), max_runs: 200) do
      {score, level} = Scorer.score(dep, findings, meta)

      expected_level =
        cond do
          score >= 80 -> :critical
          score >= 50 -> :high
          score >= 20 -> :medium
          true -> :low
        end

      assert level == expected_level
    end
  end

  property "invariant: zero findings with nil metadata scores 0" do
    check all(dep <- dependency(), max_runs: 100) do
      {score, level} = Scorer.score(dep, [], nil)
      assert score == 0
      assert level == :low
    end
  end

  property "invariant: adding a finding never decreases the score" do
    check all(
            {dep, findings, meta} <- scoring_context(),
            extra_finding <- finding(),
            max_runs: 100
          ) do
      extra_finding = %{extra_finding | dep_name: dep.name}
      {score_without, _} = Scorer.score(dep, findings, meta)
      {score_with, _} = Scorer.score(dep, [extra_finding | findings], meta)
      assert score_with >= score_without
    end
  end

  property "invariant: popularity adjustment reduces or maintains score" do
    check all(
            dep <- dependency(),
            findings <- list_of(finding(), min_length: 1, max_length: 5),
            max_runs: 100
          ) do
      findings = Enum.map(findings, fn f -> %{f | dep_name: dep.name} end)

      low_downloads = %VetCore.Types.HexMetadata{downloads: 500, owner_count: 2, description: "x"}
      high_downloads = %VetCore.Types.HexMetadata{downloads: 20_000_000, owner_count: 5, description: "x"}

      {score_low, _} = Scorer.score(dep, findings, low_downloads)
      {score_high, _} = Scorer.score(dep, findings, high_downloads)

      assert score_high <= score_low
    end
  end
end
