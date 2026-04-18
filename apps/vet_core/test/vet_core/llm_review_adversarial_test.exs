defmodule VetCore.LLMReviewAdversarialTest do
  @moduledoc """
  Unit tests for the adversarial LLM pipeline added on top of `LLMReview`.

  Covers the deterministic pieces — the parts that don't require an API key:

    * `format_refutation_prompt/2` (defense-attorney prompt)
    * `format_judge_prompt/3` (synthesis prompt)
    * `parse_judgment/2` (judge-text → `{overall, per_finding}`)
    * `apply_judgment/2` (judgment → severity/evidence transforms)
    * `review_with_refutation/2` gating (no API key, empty findings)

  Live API calls are intentionally NOT exercised — those belong in manual
  smoke tests, not CI.
  """

  use ExUnit.Case, async: true

  alias VetCore.LLMReview
  alias VetCore.Types.{Dependency, DependencyReport, Finding}

  # ---------- fixtures ------------------------------------------------------

  defp finding(attrs \\ %{}) do
    base = %Finding{
      dep_name: :suspect_pkg,
      file_path: "deps/suspect_pkg/lib/x.ex",
      line: 1,
      check_id: :system_exec,
      category: :system_exec,
      severity: :critical,
      compile_time?: true,
      evidence_level: :pattern_match,
      description: "System.cmd in module body"
    }

    Map.merge(base, Map.new(attrs))
  end

  defp dep_report(findings) do
    %DependencyReport{
      dependency: %Dependency{name: :suspect_pkg, version: "0.1.0", source: :hex},
      findings: findings,
      risk_score: 0,
      risk_level: :low
    }
  end

  # ---------- refutation prompt --------------------------------------------

  describe "format_refutation_prompt/2" do
    test "frames the model as a defense attorney" do
      prompt = LLMReview.format_refutation_prompt(dep_report([finding()]))
      assert prompt =~ "defense attorney"
      assert prompt =~ "legitimate"
      assert prompt =~ "library pattern"
    end

    test "includes every finding enumerated" do
      fs = [
        finding(description: "A"),
        finding(description: "B", category: :code_eval, check_id: :code_eval),
        finding(description: "C", category: :env_access, check_id: :env_access)
      ]

      prompt = LLMReview.format_refutation_prompt(dep_report(fs))
      assert prompt =~ "1. "
      assert prompt =~ "2. "
      assert prompt =~ "3. "
      assert prompt =~ "A"
      assert prompt =~ "B"
      assert prompt =~ "C"
    end

    test "specifies the REFUTED / CONCEDED output format" do
      prompt = LLMReview.format_refutation_prompt(dep_report([finding()]))
      assert prompt =~ "REFUTED"
      assert prompt =~ "CONCEDED"
      assert prompt =~ "FINDING #"
    end

    test "handles a report with no findings" do
      prompt = LLMReview.format_refutation_prompt(dep_report([]))
      assert prompt =~ "suspect_pkg"
      # The formatter's "(none)" sentinel survives.
      assert prompt =~ "(none)"
    end
  end

  # ---------- judge prompt --------------------------------------------------

  describe "format_judge_prompt/3" do
    test "includes both accusation and refutation verbatim" do
      accusation = "PROSECUTION: These calls are a C2 beacon."
      refutation = "DEFENSE: Standard HTTP client boilerplate."

      prompt = LLMReview.format_judge_prompt(dep_report([finding()]), accusation, refutation)

      assert prompt =~ accusation
      assert prompt =~ refutation
    end

    test "instructs the judge to be conservative (uncertainty → refuted)" do
      prompt = LLMReview.format_judge_prompt(dep_report([finding()]), "", "")
      assert prompt =~ "conservative"
      assert prompt =~ "Uncertainty should resolve as REFUTED"
    end

    test "specifies the per-finding + OVERALL format" do
      prompt = LLMReview.format_judge_prompt(dep_report([finding()]), "", "")
      assert prompt =~ "FINDING #"
      assert prompt =~ "CONFIRMED"
      assert prompt =~ "REFUTED"
      assert prompt =~ "UNCERTAIN"
      assert prompt =~ "OVERALL:"
      assert prompt =~ "MALICIOUS"
      assert prompt =~ "BENIGN"
    end
  end

  # ---------- parse_judgment ------------------------------------------------

  describe "parse_judgment/2 — happy path" do
    test "all-CONFIRMED judgment across 3 findings" do
      text = """
      FINDING #1: CONFIRMED — obvious C2 call
      FINDING #2: CONFIRMED — arbitrary code execution
      FINDING #3: CONFIRMED — reads secrets
      OVERALL: MALICIOUS
      """

      assert %{
               overall: :malicious,
               per_finding: %{1 => :confirmed, 2 => :confirmed, 3 => :confirmed}
             } = LLMReview.parse_judgment(text, 3)
    end

    test "all-REFUTED judgment across 3 findings" do
      text = """
      FINDING #1: REFUTED — normal library pattern
      FINDING #2: REFUTED — compile-time build hook
      FINDING #3: REFUTED — documented config
      OVERALL: BENIGN
      """

      assert %{
               overall: :benign,
               per_finding: %{1 => :refuted, 2 => :refuted, 3 => :refuted}
             } = LLMReview.parse_judgment(text, 3)
    end

    test "mixed verdicts" do
      text = """
      FINDING #1: CONFIRMED — malicious
      FINDING #2: REFUTED — benign
      FINDING #3: UNCERTAIN — unclear
      OVERALL: UNCERTAIN
      """

      assert %{
               overall: :uncertain,
               per_finding: %{1 => :confirmed, 2 => :refuted, 3 => :uncertain}
             } = LLMReview.parse_judgment(text, 3)
    end

    test "case-insensitive verdict tokens" do
      text = """
      Finding #1: confirmed — ok
      FINDING #2: Refuted — ok
      finding #3: UNCERTAIN — ok
      overall: malicious
      """

      %{overall: ov, per_finding: pf} = LLMReview.parse_judgment(text, 3)
      assert ov == :malicious
      assert pf[1] == :confirmed
      assert pf[2] == :refuted
      assert pf[3] == :uncertain
    end

    test "tolerates various punctuation and whitespace" do
      text = """
      FINDING    #1:     CONFIRMED — spaced out
      FINDING #2: REFUTED --- dashes
      FINDING #3:UNCERTAIN: no space
      OVERALL:   BENIGN
      """

      %{overall: ov, per_finding: pf} = LLMReview.parse_judgment(text, 3)
      assert ov == :benign
      assert pf[1] == :confirmed
      assert pf[2] == :refuted
      assert pf[3] == :uncertain
    end
  end

  describe "parse_judgment/2 — tolerating noise" do
    test "missing per-finding lines default to :uncertain" do
      # Model only mentioned findings 1 and 3; #2 is absent.
      text = """
      FINDING #1: CONFIRMED
      FINDING #3: REFUTED
      OVERALL: UNCERTAIN
      """

      %{per_finding: pf} = LLMReview.parse_judgment(text, 3)
      assert pf[1] == :confirmed
      assert pf[2] == :uncertain
      assert pf[3] == :refuted
    end

    test "completely empty text → all-uncertain, overall uncertain" do
      %{overall: ov, per_finding: pf} = LLMReview.parse_judgment("", 3)
      assert ov == :uncertain
      assert pf == %{1 => :uncertain, 2 => :uncertain, 3 => :uncertain}
    end

    test "text with no recognized verdicts → all-uncertain" do
      %{overall: ov, per_finding: pf} =
        LLMReview.parse_judgment("I cannot make a determination.\nPlease rescan.", 2)

      assert ov == :uncertain
      assert pf == %{1 => :uncertain, 2 => :uncertain}
    end

    test "n=0 yields empty per_finding map" do
      %{overall: ov, per_finding: pf} = LLMReview.parse_judgment("OVERALL: BENIGN", 0)
      assert ov == :benign
      assert pf == %{}
    end

    test "missing OVERALL line defaults to :uncertain" do
      text = "FINDING #1: CONFIRMED — a reason"
      %{overall: ov} = LLMReview.parse_judgment(text, 1)
      assert ov == :uncertain
    end

    test "unrecognised OVERALL token defaults to :uncertain" do
      text = "FINDING #1: CONFIRMED\nOVERALL: BANANAS"
      %{overall: ov} = LLMReview.parse_judgment(text, 1)
      assert ov == :uncertain
    end

    test "unknown verdict token defaults to :uncertain" do
      text = "FINDING #1: MOSTLY_GUILTY — noisy\nOVERALL: MALICIOUS"
      %{per_finding: pf} = LLMReview.parse_judgment(text, 1)
      assert pf[1] == :uncertain
    end

    test "preserves out-of-range verdict numbers without crashing" do
      text = """
      FINDING #99: CONFIRMED — not a real index
      OVERALL: UNCERTAIN
      """

      %{per_finding: pf} = LLMReview.parse_judgment(text, 2)
      # Indices 1..2 filled to :uncertain; out-of-range 99 carried through.
      assert pf[1] == :uncertain
      assert pf[2] == :uncertain
      assert pf[99] == :confirmed
    end

    test "text embedded in prose is still parsed" do
      text = """
      Let me think about this carefully.

      After review, here are my verdicts:
      FINDING #1: CONFIRMED — malicious
      and
      FINDING #2: REFUTED — benign library code

      In summary,
      OVERALL: UNCERTAIN
      """

      %{overall: ov, per_finding: pf} = LLMReview.parse_judgment(text, 2)
      assert ov == :uncertain
      assert pf[1] == :confirmed
      assert pf[2] == :refuted
    end

    test "is total — never raises on arbitrary bytes" do
      # A few adversarial strings that could plausibly break a naive parser.
      for text <- ["", "\n\n\n", "FINDING", "OVERALL:", "#1: CONFIRMED", "🔥🔥🔥"] do
        assert %{overall: _, per_finding: _} = LLMReview.parse_judgment(text, 3)
      end
    end
  end

  # ---------- apply_judgment -----------------------------------------------

  describe "apply_judgment/2" do
    test ":confirmed promotes evidence_level to :llm_confirmed" do
      f = finding(severity: :warning, evidence_level: :pattern_match)
      judgment = %{overall: :malicious, per_finding: %{1 => :confirmed}}

      [updated] = LLMReview.apply_judgment([f], judgment)

      assert updated.evidence_level == :llm_confirmed
      # Severity is NOT changed by confirmation — only evidence.
      assert updated.severity == :warning
    end

    test ":refuted demotes :critical → :warning" do
      f = finding(severity: :critical)
      judgment = %{overall: :benign, per_finding: %{1 => :refuted}}

      [updated] = LLMReview.apply_judgment([f], judgment)
      assert updated.severity == :warning
    end

    test ":refuted demotes :warning → :info" do
      f = finding(severity: :warning)
      judgment = %{overall: :benign, per_finding: %{1 => :refuted}}

      [updated] = LLMReview.apply_judgment([f], judgment)
      assert updated.severity == :info
    end

    test ":refuted on :info is a fixed point" do
      f = finding(severity: :info)
      judgment = %{overall: :benign, per_finding: %{1 => :refuted}}

      [updated] = LLMReview.apply_judgment([f], judgment)
      assert updated.severity == :info
    end

    test ":uncertain leaves the finding unchanged" do
      f = finding(severity: :critical, evidence_level: :pattern_match)
      judgment = %{overall: :uncertain, per_finding: %{1 => :uncertain}}

      [updated] = LLMReview.apply_judgment([f], judgment)
      assert updated == f
    end

    test "missing per-finding entry defaults to :uncertain (unchanged)" do
      f = finding(severity: :critical)
      judgment = %{overall: :uncertain, per_finding: %{}}

      [updated] = LLMReview.apply_judgment([f], judgment)
      assert updated == f
    end

    test "empty findings → empty result" do
      judgment = %{overall: :benign, per_finding: %{}}
      assert LLMReview.apply_judgment([], judgment) == []
    end

    test "preserves list length even with mixed verdicts" do
      fs = [
        finding(severity: :critical),
        finding(severity: :warning),
        finding(severity: :info),
        finding(severity: :critical)
      ]

      judgment = %{
        overall: :uncertain,
        per_finding: %{1 => :confirmed, 2 => :refuted, 3 => :refuted, 4 => :uncertain}
      }

      updated = LLMReview.apply_judgment(fs, judgment)
      assert length(updated) == length(fs)
    end

    test "applies per-index verdicts in order" do
      fs = [
        finding(severity: :critical, evidence_level: :pattern_match),
        finding(severity: :critical, evidence_level: :pattern_match),
        finding(severity: :critical, evidence_level: :pattern_match)
      ]

      judgment = %{
        overall: :uncertain,
        per_finding: %{1 => :confirmed, 2 => :refuted, 3 => :uncertain}
      }

      [a, b, c] = LLMReview.apply_judgment(fs, judgment)

      assert a.evidence_level == :llm_confirmed
      assert a.severity == :critical

      assert b.severity == :warning
      assert b.evidence_level == :pattern_match

      assert c == List.last(fs)
    end

    test "double-refutation does not go below :info (would be a cascading bug)" do
      # This models the scanner case where the same finding flows through
      # apply_judgment twice (e.g. re-run after cache invalidation).
      f = finding(severity: :warning)
      judgment = %{overall: :benign, per_finding: %{1 => :refuted}}

      [once] = LLMReview.apply_judgment([f], judgment)
      [twice] = LLMReview.apply_judgment([once], judgment)

      assert once.severity == :info
      assert twice.severity == :info
    end
  end

  # ---------- review_with_refutation gates ---------------------------------

  describe "review_with_refutation/2 — gates without an API key" do
    test "empty findings short-circuits to a no-op ok tuple" do
      report = dep_report([])

      assert {:ok,
              %{
                findings: [],
                judgment: %{overall: :benign, per_finding: %{}},
                accusation: "",
                refutation: ""
              }} = LLMReview.review_with_refutation(report, [])
    end

    test "missing API key (findings present) returns :missing_api_key" do
      original = System.get_env("ANTHROPIC_API_KEY")
      System.delete_env("ANTHROPIC_API_KEY")

      try do
        report = dep_report([finding()])
        assert {:error, :missing_api_key} = LLMReview.review_with_refutation(report, [])
      after
        if original, do: System.put_env("ANTHROPIC_API_KEY", original)
      end
    end

    test "empty-string API key returns :missing_api_key" do
      report = dep_report([finding()])
      assert {:error, :missing_api_key} = LLMReview.review_with_refutation(report, api_key: "")
    end
  end
end
