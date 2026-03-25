defmodule VetCore.TreeBuilderTest do
  use ExUnit.Case

  alias VetCore.TreeBuilder
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_tree_builder_test_#{:erlang.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir}
  end

  test "build/2 returns deps with children populated", %{tmp_dir: tmp_dir} do
    # Create project mix.exs that declares :parent_dep as a direct dep
    File.write!(Path.join(tmp_dir, "mix.exs"), """
    defmodule MyProject.MixProject do
      use Mix.Project

      def project do
        [app: :my_project, deps: deps()]
      end

      defp deps do
        [{:parent_dep, "~> 1.0"}]
      end
    end
    """)

    # Create parent_dep's mix.exs that depends on :child_dep
    parent_dep_dir = Path.join([tmp_dir, "deps", "parent_dep"])
    File.mkdir_p!(parent_dep_dir)
    File.write!(Path.join(parent_dep_dir, "mix.exs"), """
    defmodule ParentDep.MixProject do
      use Mix.Project

      def project do
        [app: :parent_dep, deps: deps()]
      end

      defp deps do
        [{:child_dep, "~> 0.5"}]
      end
    end
    """)

    deps = [
      %Dependency{name: :parent_dep, version: "1.0.0", source: :hex}
    ]

    assert {:ok, result} = TreeBuilder.build(tmp_dir, deps)

    assert length(result) == 1
    parent = hd(result)
    assert parent.name == :parent_dep
    assert parent.direct? == true
    assert :child_dep in parent.children
  end

  test "handles missing deps/ directory gracefully", %{tmp_dir: tmp_dir} do
    # Create a minimal mix.exs with no deps
    File.write!(Path.join(tmp_dir, "mix.exs"), """
    defmodule MyProject.MixProject do
      use Mix.Project

      def project do
        [app: :my_project, deps: deps()]
      end

      defp deps do
        []
      end
    end
    """)

    deps = [
      %Dependency{name: :missing_dep, version: "1.0.0", source: :hex}
    ]

    # Should not crash; missing dep directory means empty children
    assert {:ok, result} = TreeBuilder.build(tmp_dir, deps)

    assert length(result) == 1
    dep = hd(result)
    assert dep.children == []
    assert dep.direct? == false
  end

  test "marks non-direct deps as direct?: false (baseline comparison)", %{tmp_dir: tmp_dir} do
    File.write!(Path.join(tmp_dir, "mix.exs"), """
    defmodule MyProject.MixProject do
      use Mix.Project

      def project do
        [app: :my_project, deps: deps()]
      end

      defp deps do
        [{:direct_dep, "~> 1.0"}]
      end
    end
    """)

    deps = [
      %Dependency{name: :direct_dep, version: "1.0.0", source: :hex},
      %Dependency{name: :transitive_dep, version: "0.5.0", source: :hex}
    ]

    assert {:ok, result} = TreeBuilder.build(tmp_dir, deps)

    direct = Enum.find(result, &(&1.name == :direct_dep))
    transitive = Enum.find(result, &(&1.name == :transitive_dep))

    assert direct.direct? == true
    assert transitive.direct? == false
  end
end
