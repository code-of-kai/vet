defmodule VetCore.Property.TyposquatPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias VetCore.Metadata.TyposquatDetector

  @moduletag :property

  property "invariant: levenshtein(s, s) == 0 (reflexivity)" do
    check all(s <- string(:alphanumeric, min_length: 0, max_length: 30), max_runs: 200) do
      assert TyposquatDetector.levenshtein(s, s) == 0
    end
  end

  property "invariant: levenshtein(s, t) == levenshtein(t, s) (symmetry)" do
    check all(
            s <- string(:alphanumeric, min_length: 0, max_length: 20),
            t <- string(:alphanumeric, min_length: 0, max_length: 20),
            max_runs: 200
          ) do
      assert TyposquatDetector.levenshtein(s, t) == TyposquatDetector.levenshtein(t, s)
    end
  end

  property "invariant: levenshtein(s, \"\") == String.length(s) (distance from empty)" do
    check all(s <- string(:alphanumeric, min_length: 0, max_length: 30), max_runs: 200) do
      assert TyposquatDetector.levenshtein(s, "") == String.length(s)
    end
  end

  property "invariant: levenshtein >= abs(length difference) (lower bound)" do
    check all(
            s <- string(:alphanumeric, min_length: 0, max_length: 20),
            t <- string(:alphanumeric, min_length: 0, max_length: 20),
            max_runs: 200
          ) do
      dist = TyposquatDetector.levenshtein(s, t)
      assert dist >= abs(String.length(s) - String.length(t))
    end
  end

  property "invariant: levenshtein <= max(length(s), length(t)) (upper bound)" do
    check all(
            s <- string(:alphanumeric, min_length: 0, max_length: 20),
            t <- string(:alphanumeric, min_length: 0, max_length: 20),
            max_runs: 200
          ) do
      dist = TyposquatDetector.levenshtein(s, t)
      assert dist <= max(String.length(s), String.length(t))
    end
  end

  property "invariant: triangle inequality holds" do
    check all(
            s <- string(:alphanumeric, min_length: 1, max_length: 10),
            t <- string(:alphanumeric, min_length: 1, max_length: 10),
            u <- string(:alphanumeric, min_length: 1, max_length: 10),
            max_runs: 100
          ) do
      st = TyposquatDetector.levenshtein(s, t)
      tu = TyposquatDetector.levenshtein(t, u)
      su = TyposquatDetector.levenshtein(s, u)
      assert su <= st + tu
    end
  end

  property "invariant: levenshtein is always non-negative" do
    check all(
            s <- string(:alphanumeric, min_length: 0, max_length: 20),
            t <- string(:alphanumeric, min_length: 0, max_length: 20),
            max_runs: 200
          ) do
      assert TyposquatDetector.levenshtein(s, t) >= 0
    end
  end
end
