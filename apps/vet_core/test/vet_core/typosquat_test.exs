defmodule VetCore.Metadata.TyposquatDetectorTest do
  use ExUnit.Case

  alias VetCore.Metadata.TyposquatDetector
  alias VetCore.Types.Dependency

  describe "levenshtein/2" do
    test "identical strings return 0" do
      assert TyposquatDetector.levenshtein("phoenix", "phoenix") == 0
    end

    test "phoenix vs pheonix returns correct distance" do
      # pheonix is an adjacent swap of 'oe' -> 'eo', levenshtein = 2
      # (levenshtein counts substitutions, not transpositions)
      result = TyposquatDetector.levenshtein("phoenix", "pheonix")
      assert result == 2
    end

    test "ecto vs ectp returns 1 (adjacent swap counted as substitutions)" do
      # 'o' -> 'p' at position 3 when length is the same - actually:
      # ecto -> ectp: the 'o' becomes 'p', that's 1 substitution
      result = TyposquatDetector.levenshtein("ecto", "ectp")
      assert result == 1
    end

    test "empty strings" do
      assert TyposquatDetector.levenshtein("", "") == 0
      assert TyposquatDetector.levenshtein("abc", "") == 3
      assert TyposquatDetector.levenshtein("", "abc") == 3
    end

    test "completely different strings" do
      result = TyposquatDetector.levenshtein("abc", "xyz")
      assert result == 3
    end
  end

  describe "check_dep/1" do
    test "detects 'phoneix' as typosquat of 'phoenix'" do
      dep = %Dependency{name: :phoneix, version: "0.1.0", source: :hex}

      findings = TyposquatDetector.check_dep(dep)

      assert length(findings) >= 1
      finding = hd(findings)
      assert finding.dep_name == :phoneix
      assert finding.description =~ "phoenix"
      assert finding.category == :metadata
      assert finding.severity == :warning
    end

    test "does NOT flag 'phoenix' itself (baseline)" do
      dep = %Dependency{name: :phoenix, version: "1.7.0", source: :hex}

      findings = TyposquatDetector.check_dep(dep)

      phoenix_typosquat_findings =
        Enum.filter(findings, &(&1.description =~ "phoenix"))

      # phoenix should not be flagged as a typosquat of itself
      # (it is in the top_packages list, so it gets rejected)
      assert phoenix_typosquat_findings == []
    end

    test "does not flag completely unrelated names (baseline)" do
      dep = %Dependency{name: :my_unique_library, version: "1.0.0", source: :hex}

      findings = TyposquatDetector.check_dep(dep)

      assert findings == []
    end

    test "separator_confusion: 'phoenix-html' vs 'phoenix_html'" do
      dep = %Dependency{name: :"phoenix-html", version: "0.1.0", source: :hex}

      findings = TyposquatDetector.check_dep(dep)

      sep_findings =
        Enum.filter(findings, &(&1.description =~ "phoenix_html"))

      assert length(sep_findings) >= 1
    end
  end

  describe "check/1" do
    test "checks a list of dependencies" do
      deps = [
        %Dependency{name: :phoneix, version: "0.1.0", source: :hex},
        %Dependency{name: :safe_pkg, version: "1.0.0", source: :hex}
      ]

      findings = TyposquatDetector.check(deps)

      typosquat_findings = Enum.filter(findings, &(&1.dep_name == :phoneix))
      assert length(typosquat_findings) >= 1
    end
  end
end
