defmodule VetCore.Property.CheckPrecisionPropertyTest do
  @moduledoc """
  Precision property: for every `{module, function}` tuple NOT declared as a
  target pattern by a check (and not under a declared wildcard module), the
  check must produce zero findings.

  This complements the coverage sweep in
  `apps/vet_core/test/vet_core/checks/coverage_test.exs`:

  - The sweep proves recall: every declared pattern fires.
  - This property proves precision: nothing undeclared fires.

  Together they bound the detection surface exactly. If someone mistypes a
  declared pattern (so the original stops firing but a random atom starts
  firing), one of the two will fail.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias VetCore.Checks.{CodeEval, FileAccess, NetworkAccess}
  alias VetCore.Types.Dependency

  @moduletag :property

  # Erlang modules chosen to be benign across every check in the project.
  # Kept as a closed list so the generator never has to invent atoms at
  # runtime (atoms are globally interned and leaking them is a problem).
  @safe_erlang_modules ~w(lists maps re string rand queue proplists zlib math timer)a

  # Elixir aliases chosen the same way. Multi-segment aliases are included
  # so we exercise the `:__aliases__` AST shape with more than one atom.
  @safe_elixir_aliases [
    [:String],
    [:Enum],
    [:Map],
    [:List],
    [:Stream],
    [:Atom],
    [:Tuple],
    [:Integer],
    [:Float],
    [:Keyword],
    [:MapSet],
    [:Process]
  ]

  # Functions chosen not to overlap with any declared pattern in any check.
  @safe_functions ~w(foo bar baz quux do_work transform lookup fetch_all compute render_one)a

  setup do
    tmp_dir =
      Path.join(
        System.tmp_dir!(),
        "vet_precision_prop_#{:erlang.unique_integer([:positive])}"
      )

    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  property "CodeEval produces no findings for undeclared calls", %{tmp_dir: tmp_dir} do
    check all(
            pair <- non_declared_pair_gen(CodeEval),
            max_runs: 100
          ) do
      findings = run_check(CodeEval, tmp_dir, pair)
      assert findings == [], "unexpected findings for #{inspect(pair)}: #{inspect(findings)}"
    end
  end

  property "FileAccess produces no findings for undeclared calls", %{tmp_dir: tmp_dir} do
    check all(
            pair <- non_declared_pair_gen(FileAccess),
            max_runs: 100
          ) do
      findings = run_check(FileAccess, tmp_dir, pair)
      assert findings == [], "unexpected findings for #{inspect(pair)}: #{inspect(findings)}"
    end
  end

  property "NetworkAccess produces no findings for undeclared calls", %{tmp_dir: tmp_dir} do
    check all(
            pair <- non_declared_pair_gen(NetworkAccess),
            max_runs: 100
          ) do
      findings = run_check(NetworkAccess, tmp_dir, pair)
      assert findings == [], "unexpected findings for #{inspect(pair)}: #{inspect(findings)}"
    end
  end

  # -- Generators --------------------------------------------------------------

  # Builds a StreamData generator that yields `{module_segments, function_atom}`
  # pairs guaranteed to be absent from the given check's declared patterns and
  # not under any declared wildcard module.
  #
  # We derive the exclusion set from `check_module.target_patterns/0` at
  # test-compile time so that adding new patterns to a check automatically
  # keeps the generator safe. Wildcards are treated as "exclude the entire
  # module", which is the correct semantics for the check.
  defp non_declared_pair_gen(check_module) do
    declared_modules =
      check_module.target_patterns()
      |> Enum.map(fn {segs, _} -> segs end)
      |> MapSet.new()

    safe_erlang =
      @safe_erlang_modules
      |> Enum.map(&[&1])
      |> Enum.reject(&MapSet.member?(declared_modules, &1))

    safe_elixir =
      @safe_elixir_aliases
      |> Enum.reject(&MapSet.member?(declared_modules, &1))

    module_gen =
      StreamData.one_of([
        StreamData.member_of(safe_erlang),
        StreamData.member_of(safe_elixir)
      ])

    StreamData.tuple({module_gen, StreamData.member_of(@safe_functions)})
  end

  # -- Helpers -----------------------------------------------------------------

  defp run_check(check_module, tmp_dir, {module_segs, func}) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])

    source = """
    defmodule Vet.PrecisionFixture do
      def work(x) do
        #{render_call(module_segs, func)}
      end
    end
    """

    file = Path.join(dep_dir, "fixture.ex")
    File.write!(file, source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    findings = check_module.run(dep, tmp_dir, [])

    File.rm!(file)
    findings
  end

  defp render_call(segs, func) do
    "#{render_module(segs)}.#{func}(x)"
  end

  # Elixir aliases start with an uppercase letter (`:Code`, `:Enum`) and are
  # rendered `Code.foo(x)`. Erlang modules are lowercase atoms (`:lists`,
  # `:maps`) and are rendered `:lists.foo(x)`.
  defp render_module(segs) do
    if elixir_alias?(segs) do
      Enum.join(segs, ".")
    else
      ":#{hd(segs)}"
    end
  end

  defp elixir_alias?([first | _]) do
    case first |> Atom.to_string() |> String.first() do
      nil -> false
      c -> String.match?(c, ~r/[A-Z]/)
    end
  end
end
