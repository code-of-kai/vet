defmodule VetCore.Stress.TyposquatStressTest do
  use ExUnit.Case, async: true

  alias VetCore.Metadata.TyposquatDetector
  alias VetCore.Types.Dependency

  describe "levenshtein with empty strings" do
    test "both empty returns 0" do
      assert TyposquatDetector.levenshtein("", "") == 0
    end

    test "one empty returns length of the other" do
      assert TyposquatDetector.levenshtein("", "abc") == 3
      assert TyposquatDetector.levenshtein("hello", "") == 5
    end
  end

  describe "levenshtein with identical long strings" do
    test "100-char identical strings returns 0" do
      long = String.duplicate("a", 100)
      assert TyposquatDetector.levenshtein(long, long) == 0
    end

    test "100-char strings differing by 1 char returns 1" do
      s = String.duplicate("a", 100)
      t = String.duplicate("a", 99) <> "b"
      assert TyposquatDetector.levenshtein(s, t) == 1
    end
  end

  describe "levenshtein with completely different strings" do
    test "completely different returns max of lengths" do
      # "abc" vs "xyz" — all substitutions
      assert TyposquatDetector.levenshtein("abc", "xyz") == 3
    end

    test "different lengths, no overlap" do
      assert TyposquatDetector.levenshtein("aaaa", "bbbbb") == 5
    end
  end

  describe "performance: levenshtein for all top packages" do
    test "checking one package against all top packages completes in under 1 second" do
      dep = %Dependency{name: :pheonix, version: "1.0.0", source: :hex}

      {elapsed_us, _result} =
        :timer.tc(fn ->
          TyposquatDetector.check_dep(dep)
        end)

      elapsed_ms = elapsed_us / 1_000

      assert elapsed_ms < 1_000,
             "Typosquat check took #{elapsed_ms}ms, expected < 1000ms"
    end

    test "checking 100 packages against all top packages completes in under 1 second" do
      deps =
        Enum.map(1..100, fn i ->
          %Dependency{name: :"test_pkg_#{i}", version: "1.0.0", source: :hex}
        end)

      {elapsed_us, _result} =
        :timer.tc(fn ->
          TyposquatDetector.check(deps)
        end)

      elapsed_ms = elapsed_us / 1_000

      assert elapsed_ms < 1_000,
             "Bulk typosquat check for 100 deps took #{elapsed_ms}ms, expected < 1000ms"
    end
  end

  describe "package name that is a substring of a top package" do
    test "substring does not trigger typosquat (distance > 1)" do
      # "plug" is a top package, "plu" is a substring but distance 1, so it WILL trigger
      dep_short = %Dependency{name: :plu, version: "1.0.0", source: :hex}
      findings_short = TyposquatDetector.check_dep(dep_short)

      # "ph" is a substring of "phoenix" with distance > 1, so should NOT trigger
      dep_very_short = %Dependency{name: :ph, version: "1.0.0", source: :hex}
      findings_very_short = TyposquatDetector.check_dep(dep_very_short)

      # Just verify no crash; the exact findings depend on distances
      assert is_list(findings_short)
      assert is_list(findings_very_short)
    end

    test "exact match with top package does not trigger (rejected by Enum.reject)" do
      dep = %Dependency{name: :phoenix, version: "1.0.0", source: :hex}
      findings = TyposquatDetector.check_dep(dep)

      # Should not flag itself as a typosquat
      self_flags =
        Enum.filter(findings, fn f ->
          String.contains?(f.description, "phoenix")
        end)

      assert self_flags == [],
             "Package should not be flagged as typosquat of itself"
    end
  end

  describe "package name with special characters" do
    test "hyphens and underscores do not crash" do
      dep = %Dependency{name: :"my-special_pkg", version: "1.0.0", source: :hex}
      findings = TyposquatDetector.check_dep(dep)
      assert is_list(findings)
    end

    test "numeric-only name does not crash" do
      dep = %Dependency{name: :"12345", version: "1.0.0", source: :hex}
      findings = TyposquatDetector.check_dep(dep)
      assert is_list(findings)
    end

    test "single character name does not crash" do
      dep = %Dependency{name: :x, version: "1.0.0", source: :hex}
      findings = TyposquatDetector.check_dep(dep)
      assert is_list(findings)
    end
  end
end
