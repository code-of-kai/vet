defmodule VetCore.TreeBuilder do
  @moduledoc false

  alias VetCore.Types.Dependency

  def build(project_path, deps) do
    direct_deps = read_direct_deps(project_path)

    result =
      deps
      |> Enum.map(fn dep ->
        children = read_dep_children(project_path, dep.name)
        direct? = dep.name in direct_deps

        %Dependency{dep | children: children, direct?: direct?}
      end)

    {:ok, result}
  rescue
    e -> {:error, "Failed to build dependency tree: #{Exception.message(e)}"}
  end

  defp read_direct_deps(project_path) do
    mix_exs_path = Path.join(project_path, "mix.exs")

    case File.read(mix_exs_path) do
      {:ok, contents} -> extract_dep_names(contents)
      {:error, _} -> []
    end
  end

  defp read_dep_children(project_path, dep_name) do
    dep_mix_path = Path.join([project_path, "deps", to_string(dep_name), "mix.exs"])

    case File.read(dep_mix_path) do
      {:ok, contents} -> extract_dep_names(contents)
      {:error, _} -> []
    end
  end

  def extract_dep_names(mix_exs_content) do
    case Code.string_to_quoted(mix_exs_content) do
      {:ok, ast} -> find_deps_in_ast(ast)
      {:error, _} -> []
    end
  end

  defp find_deps_in_ast(ast) do
    {_ast, dep_names} =
      Macro.prewalk(ast, [], fn
        # Match 2-tuple dep declarations: {:dep_name, "~> 1.0"} or {:dep_name, opts}
        {name, _} = node, acc when is_atom(name) ->
          {node, [name | acc]}

        node, acc ->
          {node, acc}
      end)

    dep_names
    |> Enum.uniq()
    |> Enum.reject(&(&1 in ~w(
      deps dep project application do end def defp defmodule use if else true false nil
      app version elixir name description source_url homepage_url
      build_path config_path deps_path lockfile elixirc_paths compilers
      start_permanent consolidate_protocols aliases package links files
      licenses maintainers extra_applications mod env
      only runtime optional override manager in_umbrella path git github
      organization repo hex
    )a))
  end
end
