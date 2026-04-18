defmodule VetCore.Checks.FileHelperParsedFilesTest do
  @moduledoc """
  Unit tests for `FileHelper.parsed_files/3` — the per-dep parse cache
  boundary.

  `parsed_files/3` is how every check picks up the scanner's single
  per-dep parse. When the scanner populates `state[:parsed_files]`, checks
  must use it verbatim (no disk I/O). When the key is absent or state
  isn't a keyword list, the function falls back to `read_and_parse/2` so
  callers that instantiate a check directly still work.

  These tests pin:
    * Identity on cached input (same triples back, byte-for-byte).
    * Zero disk I/O when the cache is present (proven via unreadable path).
    * Graceful fallback for missing / nil / non-keyword state.
    * Back-compat with `read_and_parse/2` on a real fixture dep.
  """

  use ExUnit.Case, async: true

  alias VetCore.Checks.FileHelper

  setup do
    tmp =
      Path.join(
        System.tmp_dir!(),
        "vet_parsed_files_test_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)
    %{tmp: tmp}
  end

  defp write_dep!(tmp, dep_name, sources) do
    dep_dir = Path.join([tmp, "deps", to_string(dep_name), "lib"])
    File.mkdir_p!(dep_dir)

    Enum.each(sources, fn {filename, source} ->
      File.write!(Path.join(dep_dir, filename), source)
    end)

    mix_dir = Path.join([tmp, "deps", to_string(dep_name)])

    File.write!(Path.join(mix_dir, "mix.exs"), """
    defmodule #{dep_name |> to_string() |> Macro.camelize()}.MixProject do
      use Mix.Project
      def project, do: [app: :#{dep_name}, version: "1.0.0"]
    end
    """)

    dep_dir
  end

  describe "parsed_files/3 with a keyword cache" do
    test "returns the cached triples verbatim" do
      triples = [
        {"lib/a.ex", "source a", {:__block__, [], []}},
        {"lib/b.ex", "source b", {:defmodule, [], []}}
      ]

      state = [parsed_files: triples]

      assert FileHelper.parsed_files(:any_dep, "/unused", state) == triples
    end

    test "returns an empty list when the cache is explicitly empty" do
      state = [parsed_files: []]
      assert FileHelper.parsed_files(:any_dep, "/unused", state) == []
    end

    test "does NOT touch disk when cache is present", %{tmp: tmp} do
      # If the cache were ignored, read_and_parse would scan this dep and
      # return the one source we wrote. We assert instead that the cache
      # wins and the real source is never discovered.
      dep_dir = write_dep!(tmp, :real_dep, [{"real.ex", "defmodule Real do end"}])
      assert File.exists?(dep_dir)

      sentinel = [{"sentinel.ex", "# cached", :sentinel_ast}]
      state = [parsed_files: sentinel]

      assert FileHelper.parsed_files(:real_dep, tmp, state) == sentinel
    end

    test "cache takes precedence over a non-existent project path" do
      triples = [{"x.ex", "src", {:x, [], []}}]
      state = [parsed_files: triples]

      # Impossible path ensures read_and_parse would return []; we must see
      # the cache instead, confirming the cache short-circuits.
      assert FileHelper.parsed_files(:nope, "/definitely/does/not/exist", state) == triples
    end

    test "preserves triples of arbitrary (path, source, ast) shape" do
      triples = [
        {"deps/pkg/lib/weird chars ü.ex", "", nil},
        {"deps/pkg/mix.exs", String.duplicate("x", 10_000), {:defmodule, [line: 1], [:X, [do: {}]]}}
      ]

      state = [parsed_files: triples]
      assert FileHelper.parsed_files(:pkg, "/unused", state) == triples
    end

    test "ignores unrelated keyword entries" do
      triples = [{"a.ex", "src", :ast}]

      state = [
        unrelated: :thing,
        parsed_files: triples,
        another: 42,
        project_path: "/bogus"
      ]

      assert FileHelper.parsed_files(:pkg, "/unused", state) == triples
    end
  end

  describe "parsed_files/3 without a cache" do
    test "empty keyword state falls back to read_and_parse (non-existent path yields [])" do
      assert FileHelper.parsed_files(:nope, "/nonexistent/path", []) == []
    end

    test "nil state falls back gracefully" do
      assert FileHelper.parsed_files(:nope, "/nonexistent/path", nil) == []
    end

    test "non-list state falls back gracefully" do
      for bogus <- [:atom, %{}, 123, "string"] do
        assert FileHelper.parsed_files(:nope, "/nonexistent/path", bogus) == []
      end
    end

    test "keyword state without :parsed_files key falls back" do
      # Keyword list, but the specific cache key is missing → fall through.
      assert FileHelper.parsed_files(:nope, "/nonexistent/path", foo: :bar, baz: 1) == []
    end

    test "fallback actually parses a real dep directory", %{tmp: tmp} do
      write_dep!(tmp, :live_dep, [
        {"ok.ex", "defmodule Ok do\n  def x, do: 1\nend\n"}
      ])

      triples = FileHelper.parsed_files(:live_dep, tmp, [])

      paths = Enum.map(triples, &elem(&1, 0))
      assert Enum.any?(paths, &String.ends_with?(&1, "ok.ex"))
      assert Enum.any?(paths, &String.ends_with?(&1, "mix.exs"))

      # Every triple is well-shaped: {path, source, ast}.
      for {path, source, ast} <- triples do
        assert is_binary(path)
        assert is_binary(source)
        assert not is_nil(ast)
      end
    end

    test "fallback skips malformed files but returns well-formed ones", %{tmp: tmp} do
      write_dep!(tmp, :mixed_dep, [
        {"good.ex", "defmodule Good do\nend\n"},
        # Unterminated — Code.string_to_quoted returns {:error, _}
        {"broken.ex", "defmodule Broken do\n"}
      ])

      triples = FileHelper.parsed_files(:mixed_dep, tmp, [])
      paths = Enum.map(triples, &elem(&1, 0))

      assert Enum.any?(paths, &String.ends_with?(&1, "good.ex"))
      refute Enum.any?(paths, &String.ends_with?(&1, "broken.ex"))
    end
  end

  describe "cache fidelity under large input" do
    test "returns 500 triples back unchanged" do
      triples =
        for i <- 1..500 do
          {"lib/f#{i}.ex", "# source #{i}", {:mod, [i], [i]}}
        end

      state = [parsed_files: triples]
      assert FileHelper.parsed_files(:big, "/unused", state) == triples
    end
  end
end
