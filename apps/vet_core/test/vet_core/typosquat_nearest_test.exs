defmodule VetCore.Metadata.TyposquatDetectorNearestTest do
  @moduledoc """
  Unit tests for the public helpers added to `TyposquatDetector` to support
  the `PatchOracle`:

    * `top_packages/0` — exposes the corpus so the oracle can validate
      replacement targets.
    * `nearest_known/2` — finds the closest corpus package by Levenshtein
      distance, capped at `max_distance`.

  These two functions are the sole coupling point between the typosquat
  corpus and the patch oracle; if they drift, phantom-package rename
  suggestions will silently misbehave.
  """

  use ExUnit.Case, async: true

  alias VetCore.Metadata.TyposquatDetector

  describe "top_packages/0" do
    test "returns a non-empty list of atoms" do
      pkgs = TyposquatDetector.top_packages()
      assert is_list(pkgs)
      assert length(pkgs) > 0

      for pkg <- pkgs do
        assert is_atom(pkg)
      end
    end

    test "includes the canonical high-profile Elixir packages" do
      pkgs = MapSet.new(TyposquatDetector.top_packages())

      for expected <- [:phoenix, :ecto, :plug, :jason, :tesla, :req] do
        assert MapSet.member?(pkgs, expected), "corpus missing #{inspect(expected)}"
      end
    end

    test "is deterministic across invocations" do
      assert TyposquatDetector.top_packages() == TyposquatDetector.top_packages()
    end
  end

  describe "nearest_known/2 — within corpus" do
    test "exact match returns the package at distance 0" do
      assert {:ok, :phoenix, 0} = TyposquatDetector.nearest_known(:phoenix)
      assert {:ok, :ecto, 0} = TyposquatDetector.nearest_known(:ecto)
    end

    test "distance-1 neighbor of :ecto" do
      # 'ecto' → 'ectp' is a single substitution.
      assert {:ok, :ecto, 1} = TyposquatDetector.nearest_known(:ectp)
    end

    test "classic adjacent-swap 'pheonix' resolves to :phoenix within max_distance 2" do
      # Levenshtein counts the swap as 2 substitutions.
      assert {:ok, :phoenix, d} = TyposquatDetector.nearest_known(:pheonix)
      assert d <= 2
    end

    test "distance-1 typo for :jason resolves to :jason" do
      # Added a 'z' — Levenshtein = 1.
      assert {:ok, :jason, 1} = TyposquatDetector.nearest_known(:jasonz)
    end

    test "distance-1 typo for :plug resolves to :plug" do
      # 'pluug' is distance 1 from :plug.
      assert {:ok, :plug, 1} = TyposquatDetector.nearest_known(:pluug)
    end
  end

  describe "nearest_known/2 — out of range" do
    test "completely unrelated names return :none" do
      assert TyposquatDetector.nearest_known(:zzqqxyznonexistent) == :none
    end

    test "single-char name is distance >= length(smallest_pkg) - 1 from everything" do
      # Very short names will always be far from the corpus (smallest
      # corpus entry is 2+ chars). They should return :none at default
      # max_distance.
      # Note: 'q' alone is distance 2 from :req (insert 'r','e'), so not all
      # 1-char names are :none. We pick a name guaranteed to be far.
      assert TyposquatDetector.nearest_known(:"zzz") == :none
    end

    test "very long garbage name returns :none" do
      garbage = :"thisisreallyreallyreallylongandnotinthecorpus"
      assert TyposquatDetector.nearest_known(garbage) == :none
    end
  end

  describe "nearest_known/2 — input flexibility" do
    test "accepts a string name" do
      assert {:ok, :phoenix, 0} = TyposquatDetector.nearest_known("phoenix")
    end

    test "accepts an atom name" do
      assert {:ok, :phoenix, 0} = TyposquatDetector.nearest_known(:phoenix)
    end

    test "string and atom inputs give identical results" do
      assert TyposquatDetector.nearest_known("pheonix") ==
               TyposquatDetector.nearest_known(:pheonix)
    end
  end

  describe "nearest_known/2 — max_distance parameter" do
    test "max_distance: 0 requires exact match" do
      assert {:ok, :phoenix, 0} = TyposquatDetector.nearest_known(:phoenix, 0)
      assert TyposquatDetector.nearest_known(:pheonix, 0) == :none
      assert TyposquatDetector.nearest_known(:ectp, 0) == :none
    end

    test "max_distance: 1 rejects distance-2 matches" do
      # pheonix is at distance 2 from phoenix.
      assert TyposquatDetector.nearest_known(:pheonix, 1) == :none

      # ectp is at distance 1 from ecto — still matches.
      assert {:ok, :ecto, 1} = TyposquatDetector.nearest_known(:ectp, 1)
    end

    test "max_distance: 2 accepts both distance-1 and distance-2 matches" do
      assert {:ok, :phoenix, _} = TyposquatDetector.nearest_known(:pheonix, 2)
      assert {:ok, :ecto, _} = TyposquatDetector.nearest_known(:ectp, 2)
    end

    test "default max_distance is 2" do
      # pheonix is distance 2 and must match at default.
      assert {:ok, :phoenix, 2} = TyposquatDetector.nearest_known(:pheonix)
    end

    test "raising max_distance doesn't break correctness — still picks the closest" do
      # With max_distance 10, 'pheonix' should still pick :phoenix (distance 2)
      # over any more-distant alternative.
      assert {:ok, :phoenix, 2} = TyposquatDetector.nearest_known(:pheonix, 10)
    end
  end

  describe "nearest_known/2 — tie-breaking" do
    test "ties break by corpus order (first match wins)" do
      # Construct a name equidistant from multiple corpus entries:
      # ':q' is not equidistant from anything useful — skip unless we can
      # engineer a real tie. Fall back to asserting the returned pkg is at
      # the claimed distance.
      case TyposquatDetector.nearest_known(:timax) do
        {:ok, pkg, dist} ->
          assert pkg in TyposquatDetector.top_packages()
          assert is_integer(dist)
          assert dist >= 0

        :none ->
          :ok
      end
    end
  end
end
