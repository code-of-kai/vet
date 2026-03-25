defmodule VetCore.Checks.EExEval do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :code_eval

  @patterns [
    {[:EEx], :eval_string},
    {[:EEx], :eval_file},
    {[:EEx], :compile_string},
    {[:EEx], :compile_file}
  ]

  @descriptions %{
    {[:EEx], :eval_string} =>
      {"Call to EEx.eval_string — code execution via template evaluation", :critical},
    {[:EEx], :eval_file} =>
      {"Call to EEx.eval_file — code execution via file template evaluation", :critical},
    {[:EEx], :compile_string} =>
      {"Call to EEx.compile_string — template compilation", :warning},
    {[:EEx], :compile_file} =>
      {"Call to EEx.compile_file — template compilation from file", :warning}
  }

  @impl true
  def init(opts), do: opts

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      Walker.walk(ast, [&matcher(&1, &2, dep_name, source)], file_path, dep_name)
    end)
  end

  defp matcher(node, state, dep_name, source) do
    with {_type, module, func, _args, meta} <- Walker.resolve_call(node, state),
         true <- matches_pattern?(module, func) do
      {description, base_severity} = Map.fetch!(@descriptions, {module, func})
      is_ct = FileHelper.compile_time?(state.context_stack)
      severity = if is_ct, do: :critical, else: base_severity
      line = meta[:line] || 0

      %Finding{
        dep_name: dep_name,
        file_path: state.file_path,
        line: line,
        column: meta[:column],
        check_id: :eex_eval,
        category: @category,
        severity: severity,
        compile_time?: is_ct,
        snippet: FileHelper.snippet(source, line),
        description: description
      }
    else
      _ -> nil
    end
  end

  defp matches_pattern?(module, func) do
    Enum.any?(@patterns, fn {m, f} -> m == module and f == func end)
  end
end
