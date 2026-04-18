defmodule VetCore.Property.PatchOraclePropertyTest do
  @moduledoc """
  Properties for VetCore.PatchOracle — the clearwing "here's the fix"
  oracle. We property-test it offline (verify?: false) so hex.pm isn't
  hit during the run. The online verification path is covered by
  targeted unit tests.

  Core invariants:
    * `suggest/2` output is deduplicated by (action, target, version).
    * Every patch carries a rationale string.
    * Every :pin_to_version patch has a target and version.
    * Every :rename_package patch has a target atom.
    * A :version_transition finding with a previous_version in metadata
      always yields a pin_to_version patch to that exact version.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  import VetCore.Generators

  alias VetCore.Metadata.TyposquatDetector
  alias VetCore.PatchOracle
  alias VetCore.Types.{Dependency, DependencyReport, Finding, HexMetadata}

  @moduletag :property

  defp finding_with_cat(dep_name, category, overrides \\ %{}) do
    base = %Finding{
      dep_name: dep_name,
      file_path: "deps/#{dep_name}/lib/x.ex",
      line: 1,
      check_id: category,
      category: category,
      severity: :warning,
      compile_time?: false,
      description: "prop test finding"
    }

    Map.merge(base, Map.new(overrides))
  end

  defp report_with(findings, meta \\ nil) do
    %DependencyReport{
      dependency: %Dependency{name: :test_pkg, version: "1.0.0", source: :hex},
      findings: findings,
      hex_metadata: meta,
      risk_score: 0,
      risk_level: :low
    }
  end

  property "suggest/2 output is deduplicated by {action, target, version}" do
    check all(
            n <- integer(0..8),
            max_runs: 50
          ) do
      # Emit many identical typosquat findings → oracle should produce
      # at most ONE rename patch (all keyed to the same target).
      findings =
        for _ <- 1..max(n, 1)//1 do
          finding_with_cat(:test_pkg, :metadata, %{
            check_id: :typosquat,
            description: "Possible typosquat of :phoenix — distance 1"
          })
        end

      patches = PatchOracle.suggest(report_with(findings), verify?: false)
      keys = Enum.map(patches, fn p -> {p.action, p.target, p.version} end)
      assert keys == Enum.uniq(keys)
    end
  end

  property "every emitted patch has a non-empty rationale" do
    check all(
            cats <-
              list_of(
                member_of([
                  :phantom_package,
                  :metadata,
                  :version_transition,
                  :temporal_anomaly,
                  :system_exec
                ]),
                min_length: 0,
                max_length: 6
              ),
            max_runs: 50
          ) do
      findings =
        Enum.map(cats, fn cat ->
          case cat do
            :metadata ->
              finding_with_cat(:test_pkg, cat, %{
                check_id: :typosquat,
                description: "Possible typosquat of :phoenix — distance 1"
              })

            :system_exec ->
              finding_with_cat(:test_pkg, cat, %{
                severity: :critical,
                compile_time?: true
              })

            _ ->
              finding_with_cat(:test_pkg, cat)
          end
        end)

      meta = %HexMetadata{previous_version: "0.9.0", latest_version: "1.0.0"}
      patches = PatchOracle.suggest(report_with(findings, meta), verify?: false)

      for p <- patches do
        assert is_binary(p.rationale) and p.rationale != ""
      end
    end
  end

  property ":pin_to_version patches always carry target + version" do
    check all(
            cat <- member_of([:version_transition, :temporal_anomaly]),
            prev <- version_string(),
            max_runs: 50
          ) do
      findings = [finding_with_cat(:test_pkg, cat)]
      meta = %HexMetadata{previous_version: prev, latest_version: "1.0.0"}
      patches = PatchOracle.suggest(report_with(findings, meta), verify?: false)

      assert Enum.any?(patches, fn p ->
               p.action == :pin_to_version and p.target == :test_pkg and p.version == prev
             end)
    end
  end

  property ":rename_package patches always carry a target atom" do
    check all(_ <- constant(nil), max_runs: 20) do
      findings = [
        finding_with_cat(:test_pkg, :metadata, %{
          check_id: :typosquat,
          description: "Possible typosquat of :phoenix — distance 1"
        })
      ]

      patches = PatchOracle.suggest(report_with(findings), verify?: false)

      for p <- patches, p.action == :rename_package do
        assert is_atom(p.target)
        assert p.target != nil
      end
    end
  end

  property "no patches when there are no findings" do
    check all(_ <- constant(nil), max_runs: 10) do
      assert PatchOracle.suggest(report_with([]), verify?: false) == []
    end
  end

  property "phantom package finding always yields at least one patch" do
    check all(
            name <- package_name_atom(),
            max_runs: 50
          ) do
      findings = [finding_with_cat(name, :phantom_package, %{severity: :critical})]
      meta = %HexMetadata{previous_version: nil}
      patches = PatchOracle.suggest(report_with(findings, meta), verify?: false)
      assert length(patches) >= 1
    end
  end

  property "rename targets are drawn from the known-packages corpus" do
    corpus_set = MapSet.new(TyposquatDetector.top_packages())

    check all(_ <- constant(nil), max_runs: 20) do
      # Use a name that is within edit distance 2 of a known package so
      # nearest_known/1 actually returns something to rename to.
      findings = [finding_with_cat(:pheonix, :phantom_package, %{severity: :critical})]
      patches = PatchOracle.suggest(report_with(findings), verify?: false)

      for p <- patches, p.action == :rename_package do
        assert MapSet.member?(corpus_set, p.target)
      end
    end
  end
end
