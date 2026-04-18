defmodule VetCore.ScorerEvidenceTest do
  @moduledoc """
  Unit tests for the evidence ladder — the `:pattern_match → :corroborated →
  :sandbox_observed → :llm_confirmed → :known_incident` graduated confidence
  signal on `Finding`.

  These tests exercise:

    * `Scorer.evidence_weight/1` — each rung's multiplier + unknown-atom fallback.
    * The ladder's monotonicity: rung N's weight is >= rung N-1's weight.
    * End-to-end scoring via `Scorer.score/3` — the same severity/compile-time
      combo produces a strictly higher score when promoted up the ladder.
    * Default `:pattern_match` behavior when a `Finding` is built without an
      explicit evidence level.
  """

  use ExUnit.Case, async: true

  alias VetCore.Scorer
  alias VetCore.Types.{Dependency, Finding, HexMetadata}

  describe "evidence_weight/1" do
    test ":pattern_match is baseline 1.0" do
      assert Scorer.evidence_weight(:pattern_match) == 1.0
    end

    test ":corroborated weighs more than :pattern_match" do
      assert Scorer.evidence_weight(:corroborated) > Scorer.evidence_weight(:pattern_match)
      assert Scorer.evidence_weight(:corroborated) == 1.3
    end

    test ":sandbox_observed weighs more than :corroborated" do
      assert Scorer.evidence_weight(:sandbox_observed) > Scorer.evidence_weight(:corroborated)
      assert Scorer.evidence_weight(:sandbox_observed) == 1.5
    end

    test ":llm_confirmed weighs more than :sandbox_observed" do
      assert Scorer.evidence_weight(:llm_confirmed) > Scorer.evidence_weight(:sandbox_observed)
      assert Scorer.evidence_weight(:llm_confirmed) == 1.7
    end

    test ":known_incident is the top of the ladder" do
      assert Scorer.evidence_weight(:known_incident) > Scorer.evidence_weight(:llm_confirmed)
      assert Scorer.evidence_weight(:known_incident) == 2.5
    end

    test "unknown atoms default to baseline 1.0" do
      # Safety net: if someone adds a new rung in Types but forgets to update
      # the scorer, scoring must not crash. It should fall back to baseline.
      assert Scorer.evidence_weight(:no_such_rung) == 1.0
      assert Scorer.evidence_weight(nil) == 1.0
    end

    test "ladder is monotone non-decreasing" do
      ladder = [
        :pattern_match,
        :corroborated,
        :sandbox_observed,
        :llm_confirmed,
        :known_incident
      ]

      weights = Enum.map(ladder, &Scorer.evidence_weight/1)
      assert weights == Enum.sort(weights)
    end
  end

  describe "Finding default evidence_level" do
    test "a Finding built without :evidence_level defaults to :pattern_match" do
      f = %Finding{
        dep_name: :any,
        file_path: "lib/x.ex",
        line: 1,
        check_id: :system_exec,
        category: :system_exec,
        severity: :warning,
        description: "d"
      }

      assert f.evidence_level == :pattern_match
    end
  end

  describe "Scorer.score/3 with evidence promotion" do
    setup do
      dep = %Dependency{name: :pkg, version: "1.0.0", source: :hex}
      meta = %HexMetadata{downloads: 1_000_000, owner_count: 5}
      %{dep: dep, meta: meta}
    end

    defp finding_with(evidence_level) do
      %Finding{
        dep_name: :pkg,
        file_path: "lib/x.ex",
        line: 1,
        check_id: :system_exec,
        category: :system_exec,
        # Runtime warning (base 5) keeps the math easy and far enough from
        # the 100 cap that weight differences don't saturate.
        severity: :warning,
        compile_time?: false,
        evidence_level: evidence_level,
        description: "d"
      }
    end

    test "promoting :pattern_match → :corroborated strictly increases score", %{dep: dep, meta: meta} do
      {base, _} = Scorer.score(dep, [finding_with(:pattern_match)], meta)
      {corr, _} = Scorer.score(dep, [finding_with(:corroborated)], meta)
      assert corr > base
    end

    test "promoting :corroborated → :sandbox_observed strictly increases score", %{dep: dep, meta: meta} do
      {corr, _} = Scorer.score(dep, [finding_with(:corroborated)], meta)
      {sand, _} = Scorer.score(dep, [finding_with(:sandbox_observed)], meta)
      assert sand > corr
    end

    test "promoting :sandbox_observed → :llm_confirmed strictly increases score", %{dep: dep, meta: meta} do
      {sand, _} = Scorer.score(dep, [finding_with(:sandbox_observed)], meta)
      {llm, _} = Scorer.score(dep, [finding_with(:llm_confirmed)], meta)
      assert llm > sand
    end

    test "promoting :llm_confirmed → :known_incident strictly increases score", %{dep: dep, meta: meta} do
      {llm, _} = Scorer.score(dep, [finding_with(:llm_confirmed)], meta)
      {inc, _} = Scorer.score(dep, [finding_with(:known_incident)], meta)
      assert inc > llm
    end

    test "scores are monotone non-decreasing across the full ladder", %{dep: dep, meta: meta} do
      scores =
        [:pattern_match, :corroborated, :sandbox_observed, :llm_confirmed, :known_incident]
        |> Enum.map(fn level ->
          {s, _} = Scorer.score(dep, [finding_with(level)], meta)
          s
        end)

      assert scores == Enum.sort(scores)
    end

    test "known-incident on a compile-time critical can escalate risk level" do
      # Compile-time critical baseline scores 40 * 2.5 = 100 before penalties.
      dep = %Dependency{name: :pkg, version: "1.0.0", source: :hex}

      finding = %Finding{
        dep_name: :pkg,
        file_path: "deps/pkg/mix.exs",
        line: 3,
        check_id: :system_exec,
        category: :system_exec,
        severity: :critical,
        compile_time?: true,
        evidence_level: :known_incident,
        description: "known incident match"
      }

      {score, level} = Scorer.score(dep, [finding], nil)

      assert score >= 80
      assert level == :critical
    end

    test "score cannot exceed 100 even with multiple high-evidence findings" do
      dep = %Dependency{name: :pkg, version: "1.0.0", source: :hex}

      findings =
        for i <- 1..10 do
          %Finding{
            dep_name: :pkg,
            file_path: "lib/x#{i}.ex",
            line: i,
            check_id: :system_exec,
            category: :system_exec,
            severity: :critical,
            compile_time?: true,
            evidence_level: :known_incident,
            description: "d"
          }
        end

      {score, level} = Scorer.score(dep, findings, nil)

      assert score == 100
      assert level == :critical
    end

    test ":info findings stay at low-risk regardless of evidence level" do
      # Base 1 × any rung rounds to a small integer. The guarantee we care
      # about: a dep with only :info findings never climbs out of :low even
      # when promoted to the top of the ladder.
      dep = %Dependency{name: :pkg, version: "1.0.0", source: :hex}

      for level <- [:pattern_match, :corroborated, :sandbox_observed, :llm_confirmed, :known_incident] do
        f = %Finding{
          dep_name: :pkg,
          file_path: "lib/x.ex",
          line: 1,
          check_id: :env_access,
          category: :env_access,
          severity: :info,
          compile_time?: false,
          evidence_level: level,
          description: "d"
        }

        {score, risk} = Scorer.score(dep, [f], nil)
        assert score < 20, "expected :info/#{level} score < 20, got #{score}"
        assert risk == :low, "expected :info/#{level} to stay :low, got #{risk}"
      end
    end
  end
end
