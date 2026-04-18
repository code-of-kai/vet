defmodule VetCore.Property.ParseCachePropertyTest do
  @moduledoc """
  Properties for the clearwing-style per-dep parse cache. The scanner
  parses each dep once and passes the result to every check via `state`,
  instead of each check re-parsing. FileHelper.parsed_files/3 is the
  boundary between the two modes.

  Invariants:
    * When state carries :parsed_files, the function is the identity on
      the cached list (no disk I/O, no reordering).
    * When state is missing or lacks :parsed_files, the function must still
      return a well-formed list of {path, source, ast} triples.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias VetCore.Checks.FileHelper

  @moduletag :property

  defp fake_triple(path) do
    {path, "source of #{path}", {:__block__, [], []}}
  end

  defp triples_gen do
    gen all(
      paths <- list_of(string(:alphanumeric, min_length: 1, max_length: 20), min_length: 0, max_length: 30)
    ) do
      paths |> Enum.uniq() |> Enum.map(&fake_triple/1)
    end
  end

  property "cached state is returned verbatim (identity)" do
    check all(triples <- triples_gen(), max_runs: 100) do
      state = [parsed_files: triples]
      result = FileHelper.parsed_files(:any_dep, "/nonexistent/project", state)
      assert result == triples
    end
  end

  property "parsed_files with no cache key falls back without raising" do
    check all(
            extra <-
              list_of(
                tuple({
                  member_of([:foo, :bar, :baz, :other]),
                  integer()
                }),
                min_length: 0,
                max_length: 5
              ),
            max_runs: 50
          ) do
      # Unique keys only — avoid duplicate keyword entries confusing Keyword.get
      state = Enum.uniq_by(extra, &elem(&1, 0))

      # project_path points to a directory that doesn't exist → read_and_parse
      # returns [] but does not raise.
      assert [] = FileHelper.parsed_files(:no_such_dep, "/nonexistent/#{System.unique_integer()}", state)
    end
  end

  property "non-keyword state falls back gracefully" do
    check all(state <- one_of([constant(nil), constant(%{}), constant(:bogus)]), max_runs: 20) do
      result = FileHelper.parsed_files(:nope, "/also/nonexistent", state)
      assert is_list(result)
    end
  end

  property "cache returns exactly what was supplied regardless of size" do
    check all(
            n <- integer(0..50),
            max_runs: 30
          ) do
      triples = for i <- 1..max(n, 0)//1, do: fake_triple("f#{i}.ex")
      state = [parsed_files: triples]
      result = FileHelper.parsed_files(:any, "/unused", state)
      assert length(result) == n
      assert result == triples
    end
  end
end
