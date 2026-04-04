defmodule VetCore.Property.TreeBuilderPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import VetCore.Generators

  alias VetCore.TreeBuilder

  @moduletag :property

  property "invariant: direct deps always have depth 1" do
    check all(deps <- dependency_graph(), max_runs: 100) do
      result = TreeBuilder.compute_depths(deps)

      Enum.each(result, fn dep ->
        if dep.direct? do
          assert dep.depth == 1, "Direct dep #{dep.name} has depth #{dep.depth}, expected 1"
        end
      end)
    end
  end

  property "invariant: all deps have depth >= 1" do
    check all(deps <- dependency_graph(), max_runs: 100) do
      result = TreeBuilder.compute_depths(deps)

      Enum.each(result, fn dep ->
        assert dep.depth >= 1, "Dep #{dep.name} has depth #{dep.depth}, expected >= 1"
      end)
    end
  end

  property "invariant: compute_depths preserves dep count" do
    check all(deps <- dependency_graph(), max_runs: 100) do
      result = TreeBuilder.compute_depths(deps)
      assert length(result) == length(deps)
    end
  end

  property "invariant: compute_depths preserves dep names" do
    check all(deps <- dependency_graph(), max_runs: 100) do
      original_names = Enum.map(deps, & &1.name) |> MapSet.new()
      result_names = TreeBuilder.compute_depths(deps) |> Enum.map(& &1.name) |> MapSet.new()
      assert original_names == result_names
    end
  end

  property "invariant: extract_dep_names returns unique atoms" do
    check all(
            names <- list_of(package_name_atom(), min_length: 1, max_length: 5),
            max_runs: 100
          ) do
      deps_code =
        names
        |> Enum.uniq()
        |> Enum.map(fn name -> "{:#{name}, \"~> 1.0\"}" end)
        |> Enum.join(", ")

      mix_exs = """
      defmodule Test.MixProject do
        use Mix.Project
        def project, do: [app: :test, deps: deps()]
        defp deps, do: [#{deps_code}]
      end
      """

      result = TreeBuilder.extract_dep_names(mix_exs)
      assert result == Enum.uniq(result)
      assert Enum.all?(result, &is_atom/1)
    end
  end

  property "invariant: extract_dep_names never includes reserved words" do
    reserved = ~w(deps dep project application do end def defp defmodule use if else true false nil
      app version elixir name description source_url homepage_url
      build_path config_path deps_path lockfile elixirc_paths compilers
      start_permanent consolidate_protocols aliases package links files
      licenses maintainers extra_applications mod env
      only runtime optional override manager in_umbrella path git github
      organization repo hex)a

    check all(
            names <- list_of(package_name_atom(), min_length: 1, max_length: 3),
            max_runs: 100
          ) do
      deps_code =
        names
        |> Enum.uniq()
        |> Enum.map(fn name -> "{:#{name}, \"~> 1.0\"}" end)
        |> Enum.join(", ")

      mix_exs = """
      defmodule Test.MixProject do
        use Mix.Project
        def project, do: [app: :test, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
        defp deps, do: [#{deps_code}]
      end
      """

      result = TreeBuilder.extract_dep_names(mix_exs)

      Enum.each(result, fn name ->
        refute name in reserved, "Reserved word #{name} should be filtered"
      end)
    end
  end
end
