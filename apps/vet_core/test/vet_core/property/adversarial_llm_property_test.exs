defmodule VetCore.Property.AdversarialLlmPropertyTest do
  @moduledoc """
  Properties for the adversarial LLM pipeline — the clearwing-style
  accusation → refutation → judge sequence added to LLMReview.

  The LLM calls themselves are non-deterministic and require API access,
  so we property-test the deterministic pieces: the judgment parser and
  the severity/evidence transformations that apply a judgment.

  Key invariants:
    * parse_judgment/2 is total — never raises on arbitrary text.
    * parse_judgment always fills in every 1..n key (uncertainty default).
    * apply_judgment never raises severity above its original level.
    * Confirmed verdicts produce evidence_level: :llm_confirmed.
    * Info severity is a fixed point of demotion.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  import VetCore.Generators

  alias VetCore.LLMReview
  alias VetCore.Types.Finding

  @moduletag :property

  defp make_finding(severity, evidence \\ :pattern_match) do
    %Finding{
      dep_name: :test_pkg,
      file_path: "lib/x.ex",
      line: 1,
      check_id: :system_exec,
      category: :system_exec,
      severity: severity,
      compile_time?: false,
      evidence_level: evidence,
      description: "prop test"
    }
  end

  @severity_rank %{info: 0, warning: 1, critical: 2}

  # ---- parse_judgment totality + shape ------------------------------------

  property "parse_judgment is total on arbitrary strings" do
    check all(
            text <- string(:printable, min_length: 0, max_length: 500),
            n <- integer(0..10),
            max_runs: 200
          ) do
      result = LLMReview.parse_judgment(text, n)
      assert is_map(result)
      assert Map.has_key?(result, :overall)
      assert Map.has_key?(result, :per_finding)
      assert result.overall in [:malicious, :benign, :uncertain]
    end
  end

  property "parse_judgment fills in every 1..n key" do
    check all(
            text <- string(:printable, min_length: 0, max_length: 300),
            n <- integer(0..12),
            max_runs: 100
          ) do
      %{per_finding: pf} = LLMReview.parse_judgment(text, n)

      for i <- 1..max(n, 0)//1 do
        assert Map.has_key?(pf, i)
        assert pf[i] in [:confirmed, :refuted, :uncertain]
      end
    end
  end

  property "parse_judgment recognises well-formed verdict lines" do
    check all(
            n <- integer(1..8),
            verdict_tokens <- list_of(member_of(["CONFIRMED", "REFUTED", "UNCERTAIN"]), length: n),
            max_runs: 50
          ) do
      lines =
        verdict_tokens
        |> Enum.with_index(1)
        |> Enum.map_join("\n", fn {tok, idx} -> "FINDING ##{idx}: #{tok} — because reasons" end)

      text = lines <> "\nOVERALL: UNCERTAIN\n"

      %{per_finding: pf} = LLMReview.parse_judgment(text, n)

      expected =
        verdict_tokens
        |> Enum.with_index(1)
        |> Enum.map(fn {tok, idx} ->
          {idx,
           case tok do
             "CONFIRMED" -> :confirmed
             "REFUTED" -> :refuted
             _ -> :uncertain
           end}
        end)
        |> Map.new()

      for {idx, v} <- expected do
        assert pf[idx] == v
      end
    end
  end

  # ---- apply_judgment invariants -----------------------------------------

  property "apply_judgment never raises severity" do
    check all(
            sev <- severity(),
            verdict <- member_of([:confirmed, :refuted, :uncertain]),
            max_runs: 200
          ) do
      f = make_finding(sev)
      judgment = %{overall: :uncertain, per_finding: %{1 => verdict}}
      [updated] = LLMReview.apply_judgment([f], judgment)

      assert @severity_rank[updated.severity] <= @severity_rank[f.severity]
    end
  end

  property "all-confirmed judgment promotes every finding to :llm_confirmed" do
    check all(
            findings <- list_of(finding(), min_length: 0, max_length: 8),
            max_runs: 100
          ) do
      judgment = %{
        overall: :malicious,
        per_finding:
          findings
          |> Enum.with_index(1)
          |> Map.new(fn {_f, i} -> {i, :confirmed} end)
      }

      updated = LLMReview.apply_judgment(findings, judgment)

      for f <- updated, do: assert(f.evidence_level == :llm_confirmed)
    end
  end

  property "all-uncertain judgment leaves findings unchanged" do
    check all(
            findings <- list_of(finding(), min_length: 0, max_length: 8),
            max_runs: 100
          ) do
      judgment = %{
        overall: :uncertain,
        per_finding:
          findings
          |> Enum.with_index(1)
          |> Map.new(fn {_f, i} -> {i, :uncertain} end)
      }

      assert LLMReview.apply_judgment(findings, judgment) == findings
    end
  end

  property "info severity is a fixed point when refuted" do
    check all(_ <- constant(nil), max_runs: 20) do
      f = make_finding(:info, :pattern_match)
      judgment = %{overall: :benign, per_finding: %{1 => :refuted}}
      [updated] = LLMReview.apply_judgment([f], judgment)
      assert updated.severity == :info
    end
  end

  property "apply_judgment preserves finding count" do
    check all(
            findings <- list_of(finding(), min_length: 0, max_length: 10),
            max_runs: 100
          ) do
      per_finding =
        findings
        |> Enum.with_index(1)
        |> Map.new(fn {_f, i} ->
          {i, Enum.random([:confirmed, :refuted, :uncertain])}
        end)

      updated = LLMReview.apply_judgment(findings, %{overall: :uncertain, per_finding: per_finding})
      assert length(updated) == length(findings)
    end
  end

  # ---- review_with_refutation early-exit ----------------------------------

  property "review_with_refutation with no findings is a no-op success" do
    check all(_ <- constant(nil), max_runs: 5) do
      report = %VetCore.Types.DependencyReport{
        dependency: %VetCore.Types.Dependency{name: :none, version: "1.0.0", source: :hex},
        findings: [],
        risk_score: 0,
        risk_level: :low
      }

      assert {:ok, %{findings: [], judgment: %{overall: :benign}}} =
               LLMReview.review_with_refutation(report, [])
    end
  end
end
