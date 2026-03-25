defmodule VetCore.Checks.FileHelper do
  @moduledoc false

  @doc """
  Finds all .ex and .exs files in a dependency's directory, reads each file,
  parses it to AST, and returns a list of `{file_path, source, ast}` tuples.

  Files that fail to parse are silently skipped.
  """
  @spec read_and_parse(dep_name :: atom(), project_path :: String.t()) ::
          [{String.t(), String.t(), Macro.t()}]
  def read_and_parse(dep_name, project_path) do
    dep_dir = Path.join([project_path, "deps", to_string(dep_name)])

    patterns = [
      Path.join([dep_dir, "lib", "**", "*.ex"]),
      Path.join([dep_dir, "lib", "**", "*.exs"]),
      Path.join([dep_dir, "mix.exs"])
    ]

    patterns
    |> Enum.flat_map(&Path.wildcard/1)
    |> Enum.uniq()
    |> Enum.flat_map(fn file_path ->
      with {:ok, source} <- File.read(file_path),
           {:ok, ast} <- Code.string_to_quoted(source, columns: true, file: file_path) do
        [{file_path, source, ast}]
      else
        _ -> []
      end
    end)
  end

  @doc """
  Extracts a snippet from source text around the given line number.
  """
  @spec snippet(String.t(), pos_integer(), non_neg_integer()) :: String.t()
  def snippet(source, line, context_lines \\ 0) do
    lines = String.split(source, "\n")

    start = max(line - context_lines - 1, 0)
    stop = min(line + context_lines, length(lines))

    lines
    |> Enum.slice(start, stop - start)
    |> Enum.join("\n")
    |> String.trim()
  end

  @doc """
  Determines whether a match is compile-time based on its context stack.

  The context stack is a list of atoms built during AST traversal:
  - `:def` or `:defp` — inside a function definition (runtime)
  - `:defmacro` or `:defmacrop` — inside a macro definition (compile-time)
  - `:module_body` — at the top level of a defmodule (compile-time)

  Returns `true` if the code runs at compile time.
  """
  @spec compile_time?(list(atom())) :: boolean()
  def compile_time?(context_stack) do
    cond do
      :defmacro in context_stack or :defmacrop in context_stack -> true
      :def in context_stack or :defp in context_stack -> false
      true -> true
    end
  end

  @doc """
  Walks the AST with context tracking, calling `match_fn` on each node.
  `match_fn` receives `(node, context_stack)` and should return a list of findings
  (possibly empty). Returns a flat list of all findings.
  """
  @spec walk_ast(Macro.t(), (Macro.t(), list(atom()) -> [map()])) :: [map()]
  def walk_ast(ast, match_fn) do
    {_ast, {_ctx, findings}} =
      Macro.traverse(ast, {[], []}, &pre_walk(&1, &2, match_fn), &post_walk/2)

    Enum.reverse(findings)
  end

  defp pre_walk({form, _meta, _args} = node, {ctx, findings}, match_fn)
       when form in [:defmodule] do
    new_findings = match_fn.(node, ctx)
    {node, {[:module_body | ctx], new_findings ++ findings}}
  end

  defp pre_walk({form, _meta, _args} = node, {ctx, findings}, match_fn)
       when form in [:def, :defp] do
    new_findings = match_fn.(node, ctx)
    {node, {[form | ctx], new_findings ++ findings}}
  end

  defp pre_walk({form, _meta, _args} = node, {ctx, findings}, match_fn)
       when form in [:defmacro, :defmacrop] do
    new_findings = match_fn.(node, ctx)
    {node, {[form | ctx], new_findings ++ findings}}
  end

  defp pre_walk(node, {ctx, findings}, match_fn) do
    new_findings = match_fn.(node, ctx)
    {node, {ctx, new_findings ++ findings}}
  end

  defp post_walk({form, _meta, _args} = node, {[form | rest], findings})
       when form in [:defmodule, :def, :defp, :defmacro, :defmacrop] do
    {node, {rest, findings}}
  end

  defp post_walk({:defmodule, _meta, _args} = node, {[:module_body | rest], findings}) do
    {node, {rest, findings}}
  end

  defp post_walk(node, acc), do: {node, acc}
end
