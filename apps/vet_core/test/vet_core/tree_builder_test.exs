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

  describe "extract_dep_names/1" do
    test "ignores aliases (regression: Phoenix mix.exs false positives)" do
      # Bug report from a real Phoenix+Ecto project user:
      # mix aliases like `precommit`, `setup`, `ecto.setup` were being
      # treated as if they were package dependencies, then reported as
      # CRITICAL phantom packages because they don't exist on hex.pm.
      mix_exs = """
      defmodule MyApp.MixProject do
        use Mix.Project

        def project do
          [
            app: :my_app,
            version: "0.1.0",
            elixir: "~> 1.18",
            aliases: aliases(),
            deps: deps()
          ]
        end

        defp deps do
          [
            {:phoenix, "~> 1.7.0"},
            {:phoenix_ecto, "~> 4.4"},
            {:ecto_sql, "~> 3.10"},
            {:postgrex, ">= 0.0.0"},
            {:phoenix_live_view, "~> 1.0", only: :dev},
            {:bandit, "~> 1.5"}
          ]
        end

        defp aliases do
          [
            setup: ["deps.get", "ecto.setup", "assets.setup", "assets.build"],
            "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
            "ecto.reset": ["ecto.drop", "ecto.setup"],
            test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
            precommit: ["compile --warnings-as-errors", "format", "test"]
          ]
        end
      end
      """

      result = TreeBuilder.extract_dep_names(mix_exs)

      # Real deps should be found, including the 3-tuple form with options
      assert :phoenix in result
      assert :phoenix_ecto in result
      assert :ecto_sql in result
      assert :postgrex in result
      assert :phoenix_live_view in result
      assert :bandit in result

      # Alias names must NOT leak through
      refute :setup in result
      refute :precommit in result
      refute :"ecto.setup" in result
      refute :"ecto.reset" in result
      refute :test in result

      # Project metadata fields should not appear either
      refute :app in result
      refute :version in result
      refute :elixir in result
      refute :aliases in result
      refute :deps in result
    end

    test "handles single-function modules (no __block__ wrapper)" do
      # When a module has only one function, the AST is not wrapped in :__block__.
      mix_exs = """
      defmodule M.MixProject do
        defp deps do
          [{:jason, "~> 1.4"}]
        end
      end
      """

      assert [:jason] = TreeBuilder.extract_dep_names(mix_exs)
    end

    test "supports both def and defp deps definitions" do
      # def deps is rare but valid.
      mix_exs = """
      defmodule M.MixProject do
        use Mix.Project

        def project do
          [app: :m, deps: deps()]
        end

        def deps do
          [{:phoenix, "~> 1.7"}]
        end
      end
      """

      assert [:phoenix] = TreeBuilder.extract_dep_names(mix_exs)
    end

    test "returns empty list when there is no deps function" do
      mix_exs = """
      defmodule M.MixProject do
        use Mix.Project
        def project, do: [app: :m]
      end
      """

      assert [] = TreeBuilder.extract_dep_names(mix_exs)
    end

    test "returns empty list for malformed source" do
      assert [] = TreeBuilder.extract_dep_names("this is not elixir code {{{")
    end

    test "handles computed deps lists with ++ concatenation" do
      mix_exs = """
      defmodule M.MixProject do
        use Mix.Project

        def project, do: [app: :m, deps: deps()]

        defp deps do
          [{:phoenix, "~> 1.7"}] ++ dev_deps()
        end

        defp dev_deps do
          [{:credo, "~> 1.7", only: :dev}]
        end
      end
      """

      result = TreeBuilder.extract_dep_names(mix_exs)
      assert :phoenix in result
    end

    test "handles conditional deps with if expressions" do
      mix_exs = """
      defmodule M.MixProject do
        use Mix.Project

        def project, do: [app: :m, deps: deps()]

        defp deps do
          base = [{:jason, "~> 1.4"}]

          if Mix.env() == :dev do
            base ++ [{:dialyxir, "~> 1.4", only: :dev}]
          else
            base
          end
        end
      end
      """

      result = TreeBuilder.extract_dep_names(mix_exs)
      assert :jason in result
      assert :dialyxir in result
    end

    test "handles git/path deps without version strings" do
      mix_exs = """
      defmodule M.MixProject do
        use Mix.Project

        def project, do: [app: :m, deps: deps()]

        defp deps do
          [
            {:phoenix, "~> 1.7"},
            {:my_lib, git: "https://github.com/org/my_lib.git"},
            {:local_tool, path: "../tool"},
            {:umbrella_dep, in_umbrella: true}
          ]
        end
      end
      """

      result = TreeBuilder.extract_dep_names(mix_exs)
      assert :phoenix in result
      assert :my_lib in result
      assert :local_tool in result
      assert :umbrella_dep in result
    end
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
