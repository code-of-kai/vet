defmodule VetCore.Checks.AtomExhaustion do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :dos_atom_exhaustion
  @base_severity :warning

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
            check_id: :atom_exhaustion,
            category: @category,
            severity: severity,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description: description
          }]
      end
    end)
  end

  # String.to_atom/1
  defp match_pattern({{:., _, [{:__aliases__, _, [:String]}, :to_atom]}, meta, _args}) do
    {"Call to String.to_atom — DoS via atom table exhaustion",
     meta[:line] || 0, meta[:column]}
  end

  # List.to_atom/1
  defp match_pattern({{:., _, [{:__aliases__, _, [:List]}, :to_atom]}, meta, _args}) do
    {"Call to List.to_atom — DoS via atom table exhaustion",
     meta[:line] || 0, meta[:column]}
  end

  # :erlang.binary_to_atom/1,2
  defp match_pattern({{:., _, [:erlang, :binary_to_atom]}, meta, _args}) do
    {"Call to :erlang.binary_to_atom — DoS via atom table exhaustion",
     meta[:line] || 0, meta[:column]}
  end

  # :erlang.list_to_atom/1
  defp match_pattern({{:., _, [:erlang, :list_to_atom]}, meta, _args}) do
    {"Call to :erlang.list_to_atom — DoS via atom table exhaustion",
     meta[:line] || 0, meta[:column]}
  end

  defp match_pattern(_), do: nil
end
