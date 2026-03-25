defmodule VetCore.Checks.EExEval do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :code_eval

  @impl true
  def init(opts), do: opts

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      scan_ast(ast, dep_name, file_path, source)
    end)
  end

  defp scan_ast(ast, dep_name, file_path, source) do
    FileHelper.walk_ast(ast, fn node, ctx ->
      case match_pattern(node) do
        nil -> []
        {description, line, column, base_severity} ->
          is_ct = FileHelper.compile_time?(ctx)
          severity = if is_ct, do: :critical, else: base_severity

          [%Finding{
            dep_name: dep_name,
            file_path: file_path,
            line: line,
            column: column,
            check_id: :eex_eval,
            category: @category,
            severity: severity,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description: description
          }]
      end
    end)
  end

  # EEx.eval_string
  defp match_pattern({{:., _, [{:__aliases__, _, [:EEx]}, :eval_string]}, meta, _args}) do
    {"Call to EEx.eval_string — code execution via template evaluation",
     meta[:line] || 0, meta[:column], :critical}
  end

  # EEx.eval_file
  defp match_pattern({{:., _, [{:__aliases__, _, [:EEx]}, :eval_file]}, meta, _args}) do
    {"Call to EEx.eval_file — code execution via file template evaluation",
     meta[:line] || 0, meta[:column], :critical}
  end

  # EEx.compile_string
  defp match_pattern({{:., _, [{:__aliases__, _, [:EEx]}, :compile_string]}, meta, _args}) do
    {"Call to EEx.compile_string — template compilation",
     meta[:line] || 0, meta[:column], :warning}
  end

  # EEx.compile_file
  defp match_pattern({{:., _, [{:__aliases__, _, [:EEx]}, :compile_file]}, meta, _args}) do
    {"Call to EEx.compile_file — template compilation from file",
     meta[:line] || 0, meta[:column], :warning}
  end

  defp match_pattern(_), do: nil
end
