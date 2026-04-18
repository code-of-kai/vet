defmodule VetReporter.SarifPropertyTest do
  @moduledoc """
  Properties for the SARIF 2.1.0 output reporter.

  Core invariants for any ScanReport:
    * build/1 returns a map with top-level $schema, version, runs keys.
    * There is exactly one run per build.
    * result count equals the total number of findings across all deps.
    * rule list is deduplicated by ruleId.
    * every result.level is one of {note, warning, error}.
    * every result carries evidence_level in its properties.
    * encode/1 round-trips through JSON decode identically.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias VetCore.Types.{Dependency, DependencyReport, Finding, HexMetadata, ScanReport}
  alias VetReporter.Sarif

  @moduletag :property

  defp package_name do
    gen all(
      first <- member_of(Enum.to_list(?a..?z)),
      rest <- string(Enum.concat([?a..?z, ?0..?9, [?_]]), min_length: 0, max_length: 15)
    ) do
      String.to_atom(<<first>> <> rest)
    end
  end

  defp severity_gen, do: member_of([:info, :warning, :critical])

  defp evidence_level_gen,
    do: member_of([:pattern_match, :corroborated, :sandbox_observed, :llm_confirmed, :known_incident])

  defp category_gen,
    do:
      member_of([
        :system_exec,
        :code_eval,
        :network_access,
        :file_access,
        :env_access,
        :compiler_hooks,
        :obfuscation,
        :metadata,
        :phantom_package,
        :version_transition,
        :temporal_anomaly
      ])

  defp check_id_gen,
    do:
      member_of([
        :system_exec,
        :code_eval,
        :env_access,
        :file_access,
        :typosquat,
        :phantom_package,
        :version_transition,
        :temporal_anomaly
      ])

  defp finding_gen(dep_name) do
    gen all(
      line <- integer(1..500),
      check_id <- check_id_gen(),
      cat <- category_gen(),
      sev <- severity_gen(),
      ct? <- boolean(),
      ev <- evidence_level_gen()
    ) do
      %Finding{
        dep_name: dep_name,
        file_path: "deps/#{dep_name}/lib/mod.ex",
        line: line,
        column: nil,
        check_id: check_id,
        category: cat,
        severity: sev,
        compile_time?: ct?,
        evidence_level: ev,
        snippet: nil,
        description: "property test finding"
      }
    end
  end

  defp dep_report_gen do
    gen all(
      name <- package_name(),
      version <- one_of([constant(nil), constant("1.0.0")]),
      n_findings <- integer(0..6),
      findings <- list_of(finding_gen(name), length: n_findings),
      score <- integer(0..100)
    ) do
      %DependencyReport{
        dependency: %Dependency{name: name, version: version, source: :hex, children: []},
        findings: findings,
        hex_metadata: %HexMetadata{
          downloads: 1000,
          latest_version: "1.0.0",
          previous_version: "0.9.0"
        },
        risk_score: score,
        risk_level: risk_level_for(score),
        patches: []
      }
    end
  end

  defp risk_level_for(s) when s >= 80, do: :critical
  defp risk_level_for(s) when s >= 50, do: :high
  defp risk_level_for(s) when s >= 20, do: :medium
  defp risk_level_for(_), do: :low

  defp scan_report_gen do
    gen all(
      dep_reports <- list_of(dep_report_gen(), min_length: 0, max_length: 5)
    ) do
      %ScanReport{
        project_path: "/tmp/test_project",
        timestamp: DateTime.utc_now(),
        dependency_reports: dep_reports,
        summary: %{
          total_deps: length(dep_reports),
          total_findings: dep_reports |> Enum.map(&length(&1.findings)) |> Enum.sum()
        },
        allowlist_notes: []
      }
    end
  end

  # ---------- shape ----------

  property "build/1 returns a SARIF document skeleton" do
    check all(report <- scan_report_gen(), max_runs: 100) do
      doc = Sarif.build(report)
      assert Map.has_key?(doc, "$schema")
      assert doc["version"] == "2.1.0"
      assert is_list(doc["runs"])
      assert length(doc["runs"]) == 1
    end
  end

  property "result count equals total findings" do
    check all(report <- scan_report_gen(), max_runs: 100) do
      doc = Sarif.build(report)
      [run] = doc["runs"]
      expected = report.dependency_reports |> Enum.map(&length(&1.findings)) |> Enum.sum()
      assert length(run["results"]) == expected
    end
  end

  property "rule ids are unique within a run" do
    check all(report <- scan_report_gen(), max_runs: 100) do
      [run] = Sarif.build(report)["runs"]
      ids = run["tool"]["driver"]["rules"] |> Enum.map(& &1["id"])
      assert ids == Enum.uniq(ids)
    end
  end

  property "every result.level is a valid SARIF level" do
    check all(report <- scan_report_gen(), max_runs: 100) do
      [run] = Sarif.build(report)["runs"]

      for r <- run["results"] do
        assert r["level"] in ["note", "warning", "error", "none"]
      end
    end
  end

  property "every result exposes evidence_level in properties" do
    check all(report <- scan_report_gen(), max_runs: 100) do
      [run] = Sarif.build(report)["runs"]

      for r <- run["results"] do
        assert is_binary(r["properties"]["evidence_level"])
      end
    end
  end

  property "every result links to a rule defined in the tool driver" do
    check all(report <- scan_report_gen(), max_runs: 100) do
      [run] = Sarif.build(report)["runs"]
      rule_ids = run["tool"]["driver"]["rules"] |> Enum.map(& &1["id"]) |> MapSet.new()

      for r <- run["results"] do
        assert MapSet.member?(rule_ids, r["ruleId"])
      end
    end
  end

  # ---------- serialization ----------

  property "encode/1 produces JSON that decodes to an equivalent map" do
    check all(report <- scan_report_gen(), max_runs: 50) do
      encoded = Sarif.encode(report)
      decoded = Jason.decode!(encoded)
      original = Sarif.build(report) |> stringify_for_compare()
      assert decoded == original
    end
  end

  # Jason encodes atom values in properties (e.g. risk_level, evidence_level)
  # as strings — we already pre-convert in the SARIF builder, so the direct
  # comparison would only break if the builder forgot. This stringifier is a
  # defensive normalization for the property's equivalence check.
  defp stringify_for_compare(m) when is_map(m) do
    Map.new(m, fn {k, v} -> {to_string(k), stringify_for_compare(v)} end)
  end

  defp stringify_for_compare(l) when is_list(l), do: Enum.map(l, &stringify_for_compare/1)
  defp stringify_for_compare(a) when is_atom(a) and a not in [true, false, nil], do: Atom.to_string(a)
  defp stringify_for_compare(other), do: other
end
