defmodule VetCore.Checks.CodeEval do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :code_eval
  @base_severity :critical

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
        {description, line, column} ->
          is_ct = FileHelper.compile_time?(ctx)
          severity = if is_ct, do: :critical, else: @base_severity

          [%Finding{
            dep_name: dep_name,
            file_path: file_path,
            line: line,
            column: column,
            check_id: :code_eval,
            category: @category,
            severity: severity,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description: description
          }]
      end
    end)
  end

  # Code.eval_string
  defp match_pattern({{:., _, [{:__aliases__, _, [:Code]}, :eval_string]}, meta, _args}) do
    {"Call to Code.eval_string — dynamically evaluates Elixir code from a string",
     meta[:line] || 0, meta[:column]}
  end

  # Code.eval_quoted
  defp match_pattern({{:., _, [{:__aliases__, _, [:Code]}, :eval_quoted]}, meta, _args}) do
    {"Call to Code.eval_quoted — dynamically evaluates quoted Elixir expressions",
     meta[:line] || 0, meta[:column]}
  end

  # Code.eval_file
  defp match_pattern({{:., _, [{:__aliases__, _, [:Code]}, :eval_file]}, meta, _args}) do
    {"Call to Code.eval_file — evaluates an entire file as Elixir code",
     meta[:line] || 0, meta[:column]}
  end

  # Code.compile_string
  defp match_pattern({{:., _, [{:__aliases__, _, [:Code]}, :compile_string]}, meta, _args}) do
    {"Call to Code.compile_string — compiles Elixir code from a string at runtime",
     meta[:line] || 0, meta[:column]}
  end

  # Code.compile_quoted
  defp match_pattern({{:., _, [{:__aliases__, _, [:Code]}, :compile_quoted]}, meta, _args}) do
    {"Call to Code.compile_quoted — compiles quoted Elixir expressions at runtime",
     meta[:line] || 0, meta[:column]}
  end

  # :erlang.binary_to_term
  defp match_pattern({{:., _, [:erlang, :binary_to_term]}, meta, _args}) do
    {"Call to :erlang.binary_to_term — deserializes Erlang terms, potential code execution vector",
     meta[:line] || 0, meta[:column]}
  end

  # Module.create/3
  defp match_pattern({{:., _, [{:__aliases__, _, [:Module]}, :create]}, meta, _args}) do
    {"Call to Module.create/3 — dynamically creates a module at runtime",
     meta[:line] || 0, meta[:column]}
  end

  defp match_pattern(_), do: nil
end
