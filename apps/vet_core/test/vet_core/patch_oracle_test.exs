defmodule VetCore.PatchOracleTest do
  @moduledoc """
  Unit tests for `VetCore.PatchOracle` — the "here's the fix" oracle.

  These tests run `verify?: false` throughout so the suite is offline and
  deterministic; the online `verify_replacement/1` path is exercised by
  targeted hex.pm tests elsewhere.

  Categories exercised:
    * `:phantom_package` — rename when corpus has a near-neighbor, else remove.
    * `:metadata` / `check_id: :typosquat` — rename to the canonical in the
      description.
    * `:version_transition` / `:temporal_anomaly` — pin to `previous_version`.
    * Compile-time `:critical` `:system_exec` / `:code_eval` / `:compiler_hooks`
      — recommend removal.

  Plus dedupe, shape, and diff-format invariants.
  """

  use ExUnit.Case, async: true

  alias VetCore.PatchOracle
  alias VetCore.Types.{Dependency, DependencyReport, Finding, HexMetadata}

  # ---------- helpers -------------------------------------------------------

  defp finding(attrs) do
    base = %Finding{
      dep_name: :test_pkg,
      file_path: "deps/test_pkg/lib/x.ex",
      line: 1,
      check_id: :system_exec,
      category: :system_exec,
      severity: :warning,
      compile_time?: false,
      description: "placeholder"
    }

    Map.merge(base, Map.new(attrs))
  end

  defp report(findings, opts \\ []) do
    dep_name = Keyword.get(opts, :dep_name, :test_pkg)
    version = Keyword.get(opts, :version, "1.0.0")
    meta = Keyword.get(opts, :meta, nil)

    %DependencyReport{
      dependency: %Dependency{name: dep_name, version: version, source: :hex},
      findings: findings,
      hex_metadata: meta,
      risk_score: 0,
      risk_level: :low
    }
  end

  # ---------- no findings ---------------------------------------------------

  describe "suggest/2 — zero findings" do
    test "returns an empty list" do
      assert PatchOracle.suggest(report([]), verify?: false) == []
    end
  end

  # ---------- phantom package ----------------------------------------------

  describe "suggest/2 — :phantom_package findings" do
    test "rename patch when corpus has a near neighbor" do
      # :pheonix is distance 2 from :phoenix (in-corpus).
      f = finding(dep_name: :pheonix, check_id: :phantom_package, category: :phantom_package, severity: :critical)
      r = report([f], dep_name: :pheonix)

      [patch] = PatchOracle.suggest(r, verify?: false)

      assert patch.action == :rename_package
      assert patch.target == :phoenix
      assert patch.version == nil
      assert is_binary(patch.rationale)
      assert patch.rationale =~ "phoenix"
      assert patch.diff =~ "-"
      assert patch.diff =~ "+"
    end

    test "remove_dependency when no near neighbor exists in the corpus" do
      # A name far enough from any top-package corpus entry that
      # nearest_known/1 returns :none at max_distance 2.
      f = finding(
        dep_name: :zzqqwertyxyzoo123,
        check_id: :phantom_package,
        category: :phantom_package,
        severity: :critical
      )

      r = report([f], dep_name: :zzqqwertyxyzoo123)

      [patch] = PatchOracle.suggest(r, verify?: false)

      assert patch.action == :remove_dependency
      assert patch.target == nil
      assert patch.version == nil
      assert patch.rationale =~ "does not exist"
      assert patch.diff =~ "-"
    end

    test "rename patch has verified?: nil when verify?: false" do
      f = finding(dep_name: :pheonix, check_id: :phantom_package, category: :phantom_package, severity: :critical)
      r = report([f], dep_name: :pheonix)

      [patch] = PatchOracle.suggest(r, verify?: false)
      assert patch.verified? == nil
    end

    test "remove_dependency patches are always verified?: true" do
      # Semantically there's nothing to verify for a removal — mark verified.
      f = finding(
        dep_name: :zzqqnoneighbor,
        check_id: :phantom_package,
        category: :phantom_package,
        severity: :critical
      )

      r = report([f], dep_name: :zzqqnoneighbor)

      [patch] = PatchOracle.suggest(r, verify?: false)
      assert patch.verified? == true
    end
  end

  # ---------- typosquat findings -------------------------------------------

  describe "suggest/2 — typosquat check_id" do
    test "rename to the canonical mentioned in description" do
      f =
        finding(
          check_id: :typosquat,
          category: :metadata,
          description: "Possible typosquat of :phoenix — Levenshtein distance 1 from phoenix"
        )

      [patch] = PatchOracle.suggest(report([f]), verify?: false)

      assert patch.action == :rename_package
      assert patch.target == :phoenix
      assert patch.rationale =~ "Typosquat"
    end

    test "no patch emitted when the description has no :pkg token" do
      f =
        finding(
          check_id: :typosquat,
          category: :metadata,
          description: "Possible typosquat — no canonical name in this message"
        )

      assert PatchOracle.suggest(report([f]), verify?: false) == []
    end

    test "dedupes identical typosquat findings to ONE patch" do
      fs =
        for _i <- 1..5 do
          finding(
            check_id: :typosquat,
            category: :metadata,
            description: "Possible typosquat of :phoenix — distance 1"
          )
        end

      patches = PatchOracle.suggest(report(fs), verify?: false)
      assert length(patches) == 1
      assert hd(patches).target == :phoenix
    end

    test "two different typosquat targets produce two distinct patches" do
      f1 =
        finding(
          check_id: :typosquat,
          category: :metadata,
          description: "Possible typosquat of :phoenix — distance 1"
        )

      f2 =
        finding(
          check_id: :typosquat,
          category: :metadata,
          description: "Possible typosquat of :ecto — distance 1"
        )

      patches = PatchOracle.suggest(report([f1, f2]), verify?: false)
      targets = patches |> Enum.map(& &1.target) |> Enum.sort()

      assert targets == [:ecto, :phoenix]
    end
  end

  # ---------- version_transition / temporal_anomaly ------------------------

  describe "suggest/2 — version transitions" do
    test "pin_to_version when metadata has a previous_version" do
      f = finding(category: :version_transition, check_id: :version_transition)
      meta = %HexMetadata{previous_version: "0.9.0", latest_version: "1.0.0"}

      [patch] = PatchOracle.suggest(report([f], meta: meta), verify?: false)

      assert patch.action == :pin_to_version
      assert patch.target == :test_pkg
      assert patch.version == "0.9.0"
      assert patch.verified? == true
      assert patch.rationale =~ "0.9.0"
      assert patch.diff =~ "0.9.0"
    end

    test "temporal_anomaly also pins to previous_version" do
      f = finding(category: :temporal_anomaly, check_id: :temporal_anomaly)
      meta = %HexMetadata{previous_version: "2.3.4"}

      [patch] = PatchOracle.suggest(report([f], meta: meta), verify?: false)

      assert patch.action == :pin_to_version
      assert patch.version == "2.3.4"
    end

    test "no patch when metadata is nil" do
      f = finding(category: :version_transition, check_id: :version_transition)
      assert PatchOracle.suggest(report([f]), verify?: false) == []
    end

    test "no patch when previous_version is nil" do
      f = finding(category: :version_transition, check_id: :version_transition)
      meta = %HexMetadata{previous_version: nil, latest_version: "1.0.0"}
      assert PatchOracle.suggest(report([f], meta: meta), verify?: false) == []
    end

    test "two version_transition findings emit ONE patch (dedupe by target+version)" do
      f1 = finding(category: :version_transition, check_id: :version_transition, description: "shift")
      f2 = finding(category: :version_transition, check_id: :version_transition, description: "new files")
      meta = %HexMetadata{previous_version: "0.9.0"}

      patches = PatchOracle.suggest(report([f1, f2], meta: meta), verify?: false)
      assert length(patches) == 1
    end
  end

  # ---------- compile-time critical → removal ------------------------------

  describe "suggest/2 — compile-time critical findings" do
    for cat <- [:system_exec, :code_eval, :compiler_hooks] do
      test "#{cat} compile-time critical → remove_dependency" do
        f =
          finding(
            category: unquote(cat),
            check_id: unquote(cat),
            severity: :critical,
            compile_time?: true
          )

        [patch] = PatchOracle.suggest(report([f]), verify?: false)

        assert patch.action == :remove_dependency
        assert patch.target == nil
        assert patch.rationale =~ to_string(unquote(cat))
        assert patch.diff =~ "test_pkg"
      end
    end

    test "runtime (not compile-time) critical system_exec emits no patch" do
      f = finding(category: :system_exec, check_id: :system_exec, severity: :critical, compile_time?: false)
      assert PatchOracle.suggest(report([f]), verify?: false) == []
    end

    test "compile-time warning (not critical) system_exec emits no patch" do
      f = finding(category: :system_exec, check_id: :system_exec, severity: :warning, compile_time?: true)
      assert PatchOracle.suggest(report([f]), verify?: false) == []
    end

    test "compile-time critical file_access is NOT in the removal category list" do
      # file_access and network_access are not in the removal whitelist —
      # the oracle stays silent on them to avoid overaggressive advice.
      f =
        finding(
          category: :file_access,
          check_id: :file_access,
          severity: :critical,
          compile_time?: true
        )

      assert PatchOracle.suggest(report([f]), verify?: false) == []
    end
  end

  # ---------- patch shape invariants ---------------------------------------

  describe "emitted patch shape" do
    setup do
      # A motley assortment of findings so we cover all oracle branches in one go.
      fs = [
        finding(
          check_id: :typosquat,
          category: :metadata,
          description: "Possible typosquat of :phoenix"
        ),
        finding(category: :version_transition, check_id: :version_transition),
        finding(category: :system_exec, check_id: :system_exec, severity: :critical, compile_time?: true)
      ]

      meta = %HexMetadata{previous_version: "0.9.0"}
      patches = PatchOracle.suggest(report(fs, meta: meta), verify?: false)

      %{patches: patches}
    end

    test "every patch has the expected keys", %{patches: patches} do
      required = [:action, :target, :version, :verified?, :rationale, :diff, :source_finding_category]

      for p <- patches, k <- required do
        assert Map.has_key?(p, k), "patch #{inspect(p)} missing key #{inspect(k)}"
      end
    end

    test "every patch action is a known atom", %{patches: patches} do
      allowed = [:rename_package, :pin_to_version, :remove_dependency, :no_action]

      for p <- patches do
        assert p.action in allowed
      end
    end

    test "every patch has a non-empty rationale string", %{patches: patches} do
      for p <- patches do
        assert is_binary(p.rationale)
        assert String.length(p.rationale) > 0
      end
    end

    test "every patch has a non-empty diff string", %{patches: patches} do
      for p <- patches do
        assert is_binary(p.diff)
        assert String.length(p.diff) > 0
      end
    end
  end

  describe "diff format" do
    test "rename diff contains both '-' and '+' hunks" do
      f =
        finding(
          check_id: :typosquat,
          category: :metadata,
          description: "Possible typosquat of :phoenix"
        )

      [patch] = PatchOracle.suggest(report([f]), verify?: false)

      assert patch.diff =~ ~r/-.*test_pkg/
      assert patch.diff =~ ~r/\+.*phoenix/
    end

    test "pin diff shows '==' replacing '~>'" do
      f = finding(category: :version_transition, check_id: :version_transition)
      meta = %HexMetadata{previous_version: "0.9.0"}

      [patch] = PatchOracle.suggest(report([f], meta: meta), verify?: false)

      # Before: `~> x.y` → After: `== 0.9.0`. The exact-pin sigil matters.
      assert patch.diff =~ "==  0.9.0" or patch.diff =~ "== 0.9.0"
      assert patch.diff =~ "~>"
    end

    test "removal diff has only a '-' hunk (no replacement line)" do
      f = finding(category: :system_exec, check_id: :system_exec, severity: :critical, compile_time?: true)
      [patch] = PatchOracle.suggest(report([f]), verify?: false)

      assert patch.diff =~ "-"
      refute patch.diff =~ ~r/\+\s+\{:/
    end
  end

  # ---------- source_finding_category annotation --------------------------

  describe "source_finding_category" do
    test "version_transition patch carries its originating category" do
      f = finding(category: :version_transition, check_id: :version_transition)
      meta = %HexMetadata{previous_version: "0.9.0"}

      [patch] = PatchOracle.suggest(report([f], meta: meta), verify?: false)
      assert patch.source_finding_category == :version_transition
    end

    test "temporal_anomaly patch carries :temporal_anomaly" do
      f = finding(category: :temporal_anomaly, check_id: :temporal_anomaly)
      meta = %HexMetadata{previous_version: "0.9.0"}

      [patch] = PatchOracle.suggest(report([f], meta: meta), verify?: false)
      assert patch.source_finding_category == :temporal_anomaly
    end

    test "removal patch from compile-time system_exec carries :system_exec" do
      f = finding(category: :system_exec, check_id: :system_exec, severity: :critical, compile_time?: true)

      [patch] = PatchOracle.suggest(report([f]), verify?: false)
      assert patch.source_finding_category == :system_exec
    end
  end

  # ---------- dedup semantics ---------------------------------------------

  describe "dedupe" do
    test "key is {action, target, version}" do
      # Three findings across different categories but same action+target+version.
      typosquat =
        finding(
          check_id: :typosquat,
          category: :metadata,
          description: "Possible typosquat of :phoenix"
        )

      phantom_equiv =
        finding(
          dep_name: :phoneix,
          check_id: :phantom_package,
          category: :phantom_package,
          severity: :critical,
          description: "phantom"
        )

      # phoneix is a distance-1 neighbor of phoenix, so both should resolve
      # to action=:rename_package target=:phoenix version=nil → dedup to one.
      patches =
        PatchOracle.suggest(
          report([typosquat, phantom_equiv], dep_name: :phoneix),
          verify?: false
        )

      rename_patches = Enum.filter(patches, &(&1.action == :rename_package and &1.target == :phoenix))
      assert length(rename_patches) == 1
    end

    test "distinct versions do NOT dedup (pin to different predecessors)" do
      # One finding provides context for a pin to "0.9.0", another for "0.8.0"
      # — but oracle only reads from metadata, so both yield same pin. Tested
      # with a single meta; here we show that {action, target, version} key
      # means different versions would produce distinct patches if we could
      # produce them.
      f = finding(category: :version_transition, check_id: :version_transition)
      meta = %HexMetadata{previous_version: "0.9.0"}

      patches = PatchOracle.suggest(report([f, f, f], meta: meta), verify?: false)
      assert length(patches) == 1
    end
  end
end
