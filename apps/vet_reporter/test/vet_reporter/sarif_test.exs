defmodule VetReporter.SarifTest do
  @moduledoc """
  Unit tests for `VetReporter.Sarif` — the SARIF 2.1.0 generator.

  The tests pin the document's shape against what GitHub Code Scanning,
  VS Code SARIF Viewer, and the SARIF-2.1.0 schema expect:

    * Top-level `$schema`, `version`, `runs` with a single run.
    * `runs[0].tool.driver.rules` deduplicated by `check_id`.
    * Each `result` carries `ruleId`, `level`, `message`, `locations`,
      `properties`, and (when relevant) `fixes`.
    * Severity maps: `:critical → "error"`, `:warning → "warning"`,
      `:info → "note"`.
    * Vet-specific signals preserved in `result.properties`:
      `evidence_level`, `compile_time`, `risk_score`, `risk_level`, etc.
    * `PatchOracle` patches surface as `fixes` and only attach to findings
      of matching categories (`relevant_patch?/2` logic).
    * `encode/1` produces valid JSON that round-trips; `render/1` writes
      that JSON to stdout.
  """

  use ExUnit.Case, async: true

  alias VetCore.Types.{Dependency, DependencyReport, Finding, ScanReport}
  alias VetReporter.Sarif

  # ---------- fixture builders ---------------------------------------------

  defp finding(attrs \\ %{}) do
    base = %Finding{
      dep_name: :risky,
      file_path: "/tmp/p/deps/risky/lib/risky.ex",
      line: 3,
      column: 5,
      check_id: :system_exec,
      category: :system_exec,
      severity: :critical,
      compile_time?: true,
      evidence_level: :pattern_match,
      description: "System.cmd in module body",
      snippet: "System.cmd(\"curl\", [])"
    }

    Map.merge(base, Map.new(attrs))
  end

  defp dep_report(attrs) do
    defaults = %{
      dependency: %Dependency{name: :risky, version: "0.1.0", source: :hex},
      findings: [],
      hex_metadata: nil,
      risk_score: 0,
      risk_level: :low,
      patches: []
    }

    struct!(DependencyReport, Map.merge(defaults, Map.new(attrs)))
  end

  defp scan_report(dep_reports) do
    %ScanReport{
      project_path: "/tmp/p",
      timestamp: ~U[2026-04-18 12:00:00Z],
      dependency_reports: dep_reports,
      summary: %{total_deps: length(dep_reports), total_findings: 0},
      allowlist_notes: []
    }
  end

  # ---------- top-level shape ----------------------------------------------

  describe "build/1 — top-level shape" do
    test "has $schema, version 2.1.0, runs array of length 1" do
      doc = Sarif.build(scan_report([]))

      assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
      assert doc["version"] == "2.1.0"
      assert is_list(doc["runs"])
      assert length(doc["runs"]) == 1
    end

    test "run has tool, invocations, results, properties" do
      [run] = Sarif.build(scan_report([])) |> Map.fetch!("runs")

      assert is_map(run["tool"])
      assert is_list(run["invocations"])
      assert is_list(run["results"])
      assert is_map(run["properties"])
    end

    test "tool.driver has name, version, informationUri, rules" do
      [run] = Sarif.build(scan_report([]))["runs"]
      driver = run["tool"]["driver"]

      assert driver["name"] == "vet"
      assert is_binary(driver["version"])
      assert driver["informationUri"] =~ "vet"
      assert is_list(driver["rules"])
    end

    test "invocations[0] has executionSuccessful, startTimeUtc, workingDirectory" do
      [run] = Sarif.build(scan_report([]))["runs"]
      [inv] = run["invocations"]

      assert inv["executionSuccessful"] == true
      assert inv["startTimeUtc"] == "2026-04-18T12:00:00Z"
      assert inv["workingDirectory"]["uri"] == "file:///tmp/p"
    end

    test "runs[0].properties.summary carries the ScanReport summary map" do
      report = scan_report([]) |> Map.put(:summary, %{custom: :thing, total: 42})
      [run] = Sarif.build(report)["runs"]

      assert run["properties"]["summary"][:custom] == :thing
      assert run["properties"]["summary"][:total] == 42
    end
  end

  # ---------- empty cases --------------------------------------------------

  describe "build/1 — empty inputs" do
    test "no deps → no results, no rules" do
      doc = Sarif.build(scan_report([]))
      [run] = doc["runs"]

      assert run["results"] == []
      assert run["tool"]["driver"]["rules"] == []
    end

    test "deps with no findings → no results" do
      dr = dep_report(findings: [])
      [run] = Sarif.build(scan_report([dr]))["runs"]

      assert run["results"] == []
    end
  end

  # ---------- rules section ------------------------------------------------

  describe "build/1 — rules deduplication" do
    test "rule is emitted once per distinct check_id even across many findings" do
      fs =
        for i <- 1..5 do
          finding(line: i, check_id: :system_exec)
        end

      dr = dep_report(findings: fs)
      [run] = Sarif.build(scan_report([dr]))["runs"]

      rules = run["tool"]["driver"]["rules"]
      assert length(rules) == 1
      assert hd(rules)["id"] == "system_exec"
    end

    test "distinct check_ids produce distinct rules" do
      fs = [
        finding(check_id: :system_exec),
        finding(check_id: :code_eval, category: :code_eval),
        finding(check_id: :env_access, category: :env_access)
      ]

      dr = dep_report(findings: fs)
      [run] = Sarif.build(scan_report([dr]))["runs"]

      ids = run["tool"]["driver"]["rules"] |> Enum.map(& &1["id"]) |> Enum.sort()
      assert ids == ["code_eval", "env_access", "system_exec"]
    end

    test "rule has id, name, shortDescription, fullDescription, defaultConfiguration, properties" do
      dr = dep_report(findings: [finding()])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [rule] = run["tool"]["driver"]["rules"]

      assert rule["id"] == "system_exec"
      assert rule["name"] =~ ~r/[A-Z]/
      assert rule["shortDescription"]["text"] =~ "system_exec"
      assert rule["fullDescription"]["text"] =~ "system_exec"
      assert rule["defaultConfiguration"]["level"] == "warning"
      assert rule["properties"]["category"] == "system_exec"
    end

    test "rule name is CamelCased from the check_id atom" do
      dr = dep_report(findings: [finding(check_id: :atom_exhaustion, category: :obfuscation)])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [rule] = run["tool"]["driver"]["rules"]

      assert rule["name"] == "AtomExhaustion"
    end
  end

  # ---------- results section ---------------------------------------------

  describe "build/1 — results" do
    test "result count equals total findings across all deps" do
      dr1 = dep_report(findings: [finding(), finding(line: 10)])
      dr2 = dep_report(dependency: %Dependency{name: :another, version: "1.0", source: :hex}, findings: [finding(line: 20)])

      [run] = Sarif.build(scan_report([dr1, dr2]))["runs"]
      assert length(run["results"]) == 3
    end

    test "result has ruleId, level, message, locations, properties" do
      dr = dep_report(findings: [finding()])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      assert r["ruleId"] == "system_exec"
      assert is_binary(r["level"])
      assert r["message"]["text"] =~ "System.cmd"
      assert is_list(r["locations"])
      assert is_map(r["properties"])
    end

    test "every result's ruleId references a rule in the driver's rule list" do
      dr = dep_report(findings: [finding(check_id: :code_eval, category: :code_eval), finding()])
      [run] = Sarif.build(scan_report([dr]))["runs"]

      rule_ids = run["tool"]["driver"]["rules"] |> Enum.map(& &1["id"]) |> MapSet.new()

      for r <- run["results"] do
        assert MapSet.member?(rule_ids, r["ruleId"])
      end
    end
  end

  # ---------- severity mapping ---------------------------------------------

  describe "build/1 — severity → SARIF level" do
    test "critical → error" do
      dr = dep_report(findings: [finding(severity: :critical)])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      assert r["level"] == "error"
    end

    test "warning → warning" do
      dr = dep_report(findings: [finding(severity: :warning)])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      assert r["level"] == "warning"
    end

    test "info → note" do
      dr = dep_report(findings: [finding(severity: :info)])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      assert r["level"] == "note"
    end
  end

  # ---------- location ----------------------------------------------------

  describe "build/1 — location URI shortening" do
    test "absolute path containing /deps/ becomes repo-relative deps/..." do
      f = finding(file_path: "/some/wildly/nested/path/deps/risky/lib/x.ex")
      dr = dep_report(findings: [f])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      [loc] = r["locations"]
      assert loc["physicalLocation"]["artifactLocation"]["uri"] == "deps/risky/lib/x.ex"
    end

    test "mix.lock preserved as-is" do
      f = finding(file_path: "mix.lock")
      dr = dep_report(findings: [f])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      [loc] = r["locations"]
      assert loc["physicalLocation"]["artifactLocation"]["uri"] == "mix.lock"
    end

    test "mix.exs preserved as-is" do
      f = finding(file_path: "mix.exs")
      dr = dep_report(findings: [f])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      [loc] = r["locations"]
      assert loc["physicalLocation"]["artifactLocation"]["uri"] == "mix.exs"
    end

    test "synthetic pseudo-paths route to mix.lock" do
      for synthetic <- ["version_diff", "version_diff_lookback", "temporal_reputation"] do
        f = finding(file_path: synthetic)
        dr = dep_report(findings: [f])
        [run] = Sarif.build(scan_report([dr]))["runs"]
        [r] = run["results"]

        [loc] = r["locations"]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "mix.lock", "expected #{synthetic} to route to mix.lock, got #{uri}"
      end
    end

    test "region carries startLine and startColumn (if column > 0)" do
      f = finding(line: 42, column: 7)
      dr = dep_report(findings: [f])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]
      [loc] = r["locations"]

      region = loc["physicalLocation"]["region"]
      assert region["startLine"] == 42
      assert region["startColumn"] == 7
    end

    test "nil column is omitted from region" do
      f = finding(line: 42, column: nil)
      dr = dep_report(findings: [f])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]
      [loc] = r["locations"]

      region = loc["physicalLocation"]["region"]
      assert region["startLine"] == 42
      refute Map.has_key?(region, "startColumn")
    end

    test "startLine is coerced to at least 1 (never 0 or negative)" do
      # SARIF requires startLine >= 1.
      for bogus_line <- [0, -1, -99] do
        f = finding(line: bogus_line)
        dr = dep_report(findings: [f])
        [run] = Sarif.build(scan_report([dr]))["runs"]
        [r] = run["results"]
        [loc] = r["locations"]

        assert loc["physicalLocation"]["region"]["startLine"] == 1
      end
    end
  end

  # ---------- properties on each result ------------------------------------

  describe "build/1 — result.properties preserves Vet signals" do
    test "carries dep_name, dep_version, category, evidence_level, compile_time, risk_score, risk_level" do
      f = finding(evidence_level: :llm_confirmed)

      dr =
        dep_report(
          dependency: %Dependency{name: :risky, version: "2.1.3", source: :hex},
          findings: [f],
          risk_score: 88,
          risk_level: :critical
        )

      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      assert r["properties"]["dep_name"] == "risky"
      assert r["properties"]["dep_version"] == "2.1.3"
      assert r["properties"]["category"] == "system_exec"
      assert r["properties"]["evidence_level"] == "llm_confirmed"
      assert r["properties"]["compile_time"] == true
      assert r["properties"]["risk_score"] == 88
      assert r["properties"]["risk_level"] == "critical"
    end

    test "nil fields (snippet, dep_version) are filtered out" do
      f = finding(snippet: nil)
      dr = dep_report(
        dependency: %Dependency{name: :risky, version: nil, source: :hex},
        findings: [f]
      )

      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      refute Map.has_key?(r["properties"], "snippet")
      refute Map.has_key?(r["properties"], "dep_version")
    end

    test "compile_time: false is preserved as false (not stripped)" do
      f = finding(compile_time?: false)
      dr = dep_report(findings: [f])

      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      # false is a legitimate value; `reject_nil` should only filter nils.
      assert r["properties"]["compile_time"] == false
    end
  end

  # ---------- fixes (PatchOracle patches → SARIF fixes) -------------------

  defp patch(attrs) do
    defaults = %{
      action: :rename_package,
      target: :phoenix,
      version: nil,
      verified?: nil,
      rationale: "rename rationale",
      diff: "-old\n+new",
      source_finding_category: :metadata
    }

    Map.merge(defaults, Map.new(attrs))
  end

  describe "build/1 — fixes attachment" do
    test "no patches → no fixes field on results" do
      dr = dep_report(findings: [finding()])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      refute Map.has_key?(r, "fixes")
    end

    test "rename_package patch attaches ONLY to :metadata / :phantom_package findings" do
      fs = [
        finding(category: :metadata, check_id: :typosquat),
        finding(category: :system_exec, check_id: :system_exec)
      ]

      p = patch(action: :rename_package, target: :phoenix, source_finding_category: :metadata)
      dr = dep_report(findings: fs, patches: [p])

      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r1, r2] = run["results"]

      assert r1["ruleId"] == "typosquat"
      assert Map.has_key?(r1, "fixes")
      assert length(r1["fixes"]) == 1

      assert r2["ruleId"] == "system_exec"
      refute Map.has_key?(r2, "fixes")
    end

    # Adversarial: the comment at apps/vet_reporter/lib/vet_reporter/sarif.ex:172-174
    # states "Rename patches only attach to typosquat/phantom findings." The
    # implementation at line 176, however, whitelists the entire :metadata
    # CATEGORY — not just the :typosquat check_id. Any future non-typosquat
    # check that also emits category :metadata (e.g. :repo_integrity_mismatch,
    # :maintainer_change) would silently pick up a "rename to a different
    # package" fix suggestion that has nothing to do with the actual problem.
    #
    # This test pins the current behavior and flags the discrepancy. If the
    # impl is narrowed to a check_id whitelist (matching the comment's
    # stated intent) OR the comment is rewritten to say "category :metadata
    # or :phantom_package", update this test accordingly.
    test "rename_package CURRENTLY attaches to ALL :metadata findings, not just :typosquat (contradicts adjacent code comment)" do
      fs = [
        finding(category: :metadata, check_id: :typosquat),
        finding(category: :metadata, check_id: :repo_integrity_mismatch)
      ]

      p = patch(action: :rename_package, target: :phoenix, source_finding_category: :metadata)
      dr = dep_report(findings: fs, patches: [p])

      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r1, r2] = run["results"]

      # Typosquat — the comment's intended target — correctly gets the fix.
      assert r1["ruleId"] == "typosquat"
      assert Map.has_key?(r1, "fixes")

      # Non-typosquat :metadata finding ALSO gets the rename fix. Per the
      # comment this should NOT happen; per the implementation it does.
      assert r2["ruleId"] == "repo_integrity_mismatch"

      assert Map.has_key?(r2, "fixes"),
             "If the rename-patch filter is narrowed to the :typosquat check_id " <>
               "(matching the comment at sarif.ex:172-174), this assertion should " <>
               "flip from assert to refute."
    end

    test "remove_dependency patch attaches to EVERY finding on that dep" do
      fs = [
        finding(category: :system_exec, check_id: :system_exec),
        finding(category: :code_eval, check_id: :code_eval),
        finding(category: :env_access, check_id: :env_access)
      ]

      p = patch(action: :remove_dependency, target: nil, source_finding_category: :system_exec)
      dr = dep_report(findings: fs, patches: [p])

      [run] = Sarif.build(scan_report([dr]))["runs"]

      for r <- run["results"] do
        assert Map.has_key?(r, "fixes")
      end
    end

    test "pin_to_version patch attaches to same-category findings" do
      fs = [
        finding(category: :version_transition, check_id: :version_transition),
        finding(category: :system_exec, check_id: :system_exec)
      ]

      p =
        patch(
          action: :pin_to_version,
          target: :risky,
          version: "0.9.0",
          source_finding_category: :version_transition
        )

      dr = dep_report(findings: fs, patches: [p])

      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r_vt, r_se] = run["results"]

      assert r_vt["ruleId"] == "version_transition"
      assert Map.has_key?(r_vt, "fixes")

      assert r_se["ruleId"] == "system_exec"
      refute Map.has_key?(r_se, "fixes")
    end

    test "fix entry has description + properties with action/target/version/verified/diff" do
      f = finding(category: :metadata, check_id: :typosquat)

      p =
        patch(
          action: :rename_package,
          target: :phoenix,
          version: nil,
          verified?: true,
          rationale: "Use :phoenix instead",
          diff: "-bad\n+good",
          source_finding_category: :metadata
        )

      dr = dep_report(findings: [f], patches: [p])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]
      [fix] = r["fixes"]

      assert fix["description"]["text"] == "Use :phoenix instead"
      assert fix["properties"]["action"] == "rename_package"
      assert fix["properties"]["target"] == "phoenix"
      assert fix["properties"]["verified"] == true
      assert fix["properties"]["diff"] =~ "-bad"
      refute Map.has_key?(fix["properties"], "version")
    end

    test "multiple patches on the same finding produce multiple fixes" do
      f = finding(category: :version_transition, check_id: :version_transition)

      p1 =
        patch(
          action: :pin_to_version,
          target: :risky,
          version: "0.9.0",
          source_finding_category: :version_transition
        )

      p2 = patch(action: :remove_dependency, target: nil, source_finding_category: :version_transition)

      dr = dep_report(findings: [f], patches: [p1, p2])
      [run] = Sarif.build(scan_report([dr]))["runs"]
      [r] = run["results"]

      assert length(r["fixes"]) == 2
    end
  end

  # ---------- encode / render ---------------------------------------------

  describe "encode/1" do
    test "returns valid, parseable JSON" do
      dr = dep_report(findings: [finding()])
      json = Sarif.encode(scan_report([dr]))

      assert is_binary(json)
      assert {:ok, _decoded} = Jason.decode(json)
    end

    test "output is pretty-printed (has newlines)" do
      dr = dep_report(findings: [finding()])
      json = Sarif.encode(scan_report([dr]))

      assert String.contains?(json, "\n")
    end

    test "JSON round-trip preserves top-level shape" do
      dr = dep_report(findings: [finding()])
      json = Sarif.encode(scan_report([dr]))
      {:ok, decoded} = Jason.decode(json)

      assert decoded["version"] == "2.1.0"
      assert is_list(decoded["runs"])
      assert length(decoded["runs"]) == 1
    end

    test "round-trip preserves result fields for a known finding" do
      f =
        finding(
          evidence_level: :llm_confirmed,
          severity: :critical,
          compile_time?: true,
          line: 42
        )

      dr = dep_report(findings: [f], risk_score: 75, risk_level: :high)

      json = Sarif.encode(scan_report([dr]))
      {:ok, decoded} = Jason.decode(json)

      [run] = decoded["runs"]
      [r] = run["results"]

      assert r["level"] == "error"
      assert r["properties"]["evidence_level"] == "llm_confirmed"
      assert r["properties"]["compile_time"] == true
      assert r["properties"]["risk_score"] == 75
      assert r["locations"] |> hd() |> get_in(["physicalLocation", "region", "startLine"]) == 42
    end
  end

  describe "render/1" do
    test "writes pretty JSON to stdout" do
      dr = dep_report(findings: [finding()])
      report = scan_report([dr])

      output = ExUnit.CaptureIO.capture_io(fn -> Sarif.render(report) end)

      assert {:ok, decoded} = Jason.decode(output)
      assert decoded["version"] == "2.1.0"
    end

    test "render/1 returns :ok" do
      dr = dep_report(findings: [])

      # IO.puts returns :ok; render wraps that.
      assert ExUnit.CaptureIO.capture_io(fn ->
               assert Sarif.render(scan_report([dr])) == :ok
             end) =~ "2.1.0"
    end
  end
end
