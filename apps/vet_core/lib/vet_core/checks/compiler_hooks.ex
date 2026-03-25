defmodule VetCore.Checks.CompilerHooks do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

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
        {description, line, column, severity} ->
          is_ct = FileHelper.compile_time?(ctx)

          [%Finding{
            dep_name: dep_name,
            file_path: file_path,
            line: line,
            column: column,
            check_id: :compiler_hooks,
            category: :compiler_hooks,
            severity: severity,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description: description
          }]
      end
    end)
  end

  # @before_compile — critical: runs arbitrary code at compile time
  defp match_pattern({:@, meta, [{:before_compile, _, _}]}) do
    {"@before_compile callback — code runs at compile time, can execute arbitrary logic",
     meta[:line] || 0, meta[:column], :critical}
  end

  # @after_compile — critical: runs arbitrary code after compilation
  defp match_pattern({:@, meta, [{:after_compile, _, _}]}) do
    {"@after_compile callback — code runs after compilation, can execute arbitrary logic",
     meta[:line] || 0, meta[:column], :critical}
  end

  # @external_resource — warning: reads files at compile time
  defp match_pattern({:@, meta, [{:external_resource, _, _}]}) do
    {"@external_resource — triggers recompilation based on external file, runs at compile time",
     meta[:line] || 0, meta[:column], :warning}
  end

  # Custom compilers in mix.exs: `compilers: [...]`
  defp match_pattern({:compilers, meta, [[_ | _] = _compilers]}) do
    {"Custom compilers defined in mix.exs — may execute arbitrary code during compilation",
     meta[:line] || 0, meta[:column], :critical}
  end

  # compilers: [...] as keyword in a keyword list
  defp match_pattern({:compilers, value}) when is_list(value) do
    nil
  end

  # Mix.compilers() customization
  defp match_pattern({{:., _, [{:__aliases__, _, [:Mix]}, :compilers]}, meta, _args}) do
    {"Mix.compilers() usage — may customize the compilation pipeline",
     meta[:line] || 0, meta[:column], :critical}
  end

  defp match_pattern(_), do: nil
end
