defmodule VetCore.TreeBuilder do
  @moduledoc false

  alias VetCore.Types.Dependency

  # Keyword options that appear inside dep tuples like
  # {:phoenix, "~> 1.7", only: :dev, runtime: false, optional: true}
  @dep_keyword_opts ~w(
    only runtime optional override manager in_umbrella path git github
    organization repo hex env compile_env app sparse system_env targets
    branch tag ref submodules subdir
  )a

  def build(project_path, deps) do
    direct_deps = read_direct_deps(project_path)

    result =
      deps
      |> Enum.map(fn dep ->
        children = read_dep_children(project_path, dep.name)
        direct? = dep.name in direct_deps

        %Dependency{dep | children: children, direct?: direct?}
      end)

    result = compute_depths(result)

    {:ok, result}
  rescue
    e -> {:error, "Failed to build dependency tree: #{Exception.message(e)}"}
  end

  @doc """
  Compute dependency depth via BFS from direct deps.
  Direct deps are depth 1, their children depth 2, and so on.
  """
  def compute_depths(deps) do
    deps_by_name = Map.new(deps, &{&1.name, &1})

    # Seed BFS with direct deps at depth 1
    initial_queue =
      deps
      |> Enum.filter(& &1.direct?)
      |> Enum.map(&{&1.name, 1})

    depths = bfs_depths(initial_queue, deps_by_name, %{})

    Enum.map(deps, fn dep ->
      %{dep | depth: Map.get(depths, dep.name, 1)}
    end)
  end

  defp bfs_depths([], _deps_by_name, visited), do: visited

  defp bfs_depths([{name, depth} | rest], deps_by_name, visited) do
    if Map.has_key?(visited, name) do
      bfs_depths(rest, deps_by_name, visited)
    else
      visited = Map.put(visited, name, depth)

      children =
        case Map.get(deps_by_name, name) do
          %{children: children} when is_list(children) -> children
          _ -> []
        end

      new_entries =
        children
        |> Enum.reject(&Map.has_key?(visited, &1))
        |> Enum.map(&{&1, depth + 1})

      bfs_depths(rest ++ new_entries, deps_by_name, visited)
    end
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

  @doc """
  Extract dependency names from a mix.exs file's source.

  Walks ONLY the body of the `deps` function, not the entire module AST.
  This avoids false positives from `aliases`, `releases`, or any other
  function that returns keyword lists.
  """
  def extract_dep_names(mix_exs_content) do
    case Code.string_to_quoted(mix_exs_content) do
      {:ok, ast} -> find_deps_in_ast(ast)
      {:error, _} -> []
    end
  end

  defp find_deps_in_ast(ast) do
    case extract_function_body(ast, :deps) do
      nil ->
        []

      deps_body ->
        deps_body
        |> collect_dep_names([])
        |> Enum.uniq()
    end
  end

  # Walk the deps function body collecting dep names.
  # Uses Macro.prewalk to traverse the full AST so that computed deps
  # lists (e.g. `base_deps() ++ dev_deps()`, `if Mix.env() == :dev ...`)
  # are explored, not just literal lists.
  #
  # Matches:
  #   {:phoenix, "~> 1.7"}                          — 2-tuple with version string
  #   {:phoenix, "~> 1.7", only: :dev}              — 3-tuple, AST: {:{}, _, [name, ...]}
  #   {:my_dep, git: "https://..."}                  — 2-tuple with keyword opts (git/path deps)
  #   {:my_dep, path: "../tool", runtime: false}     — 3-tuple keyword opts
  defp collect_dep_names(ast, acc) do
    {_ast, names} =
      Macro.prewalk(ast, acc, fn
        # 2-tuple: {:name, "~> 1.0"}
        {name, version} = node, names
        when is_atom(name) and is_binary(version) and name not in @dep_keyword_opts ->
          {node, [name | names]}

        # 2-tuple: {:name, git: "...", ...} or {:name, path: "..."}
        {name, opts} = node, names
        when is_atom(name) and is_list(opts) and name not in @dep_keyword_opts ->
          if Keyword.keyword?(opts) do
            {node, [name | names]}
          else
            {node, names}
          end

        # 3-tuple: {:name, "~> 1.0", only: :dev} — AST form {:{}, meta, [name, version, opts]}
        {:{}, _meta, [name, version | _opts]} = node, names
        when is_atom(name) and is_binary(version) and name not in @dep_keyword_opts ->
          {node, [name | names]}

        # 3-tuple: {:name, [git: "..."], [only: :dev]} — git/path with extra opts
        {:{}, _meta, [name, opts | _rest]} = node, names
        when is_atom(name) and is_list(opts) and name not in @dep_keyword_opts ->
          if Keyword.keyword?(opts) do
            {node, [name | names]}
          else
            {node, names}
          end

        node, names ->
          {node, names}
      end)

    names
  end

  # Find a top-level def/defp by name and return its body.
  # Handles single-clause modules and multi-clause __block__ modules.
  defp extract_function_body(ast, func_name) do
    case ast do
      {:defmodule, _meta, [_module, [do: module_body]]} ->
        extract_from_module_body(module_body, func_name)

      _ ->
        nil
    end
  end

  defp extract_from_module_body({:__block__, _meta, clauses}, func_name) do
    Enum.find_value(clauses, nil, fn clause ->
      match_function_clause(clause, func_name)
    end)
  end

  defp extract_from_module_body(single_clause, func_name) do
    match_function_clause(single_clause, func_name)
  end

  defp match_function_clause(
         {form, _meta, [{name, _fn_meta, _args}, [do: fn_body]]},
         func_name
       )
       when form in [:def, :defp] and name == func_name do
    fn_body
  end

  defp match_function_clause(_clause, _func_name), do: nil
end
