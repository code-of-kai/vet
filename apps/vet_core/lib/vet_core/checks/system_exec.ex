defmodule VetCore.Checks.SystemExec do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :system_exec
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
            check_id: :system_exec,
            category: @category,
            severity: severity,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description: description
          }]
      end
    end)
  end

  # System.cmd/2,3
  defp match_pattern({{:., _, [{:__aliases__, _, [:System]}, :cmd]}, meta, _args}) do
    {"Call to System.cmd/2,3 — executes an external system command",
     meta[:line] || 0, meta[:column]}
  end

  # System.shell/1,2
  defp match_pattern({{:., _, [{:__aliases__, _, [:System]}, :shell]}, meta, _args}) do
    {"Call to System.shell — executes a shell command",
     meta[:line] || 0, meta[:column]}
  end

  # System.find_executable/1
  defp match_pattern({{:., _, [{:__aliases__, _, [:System]}, :find_executable]}, meta, _args}) do
    {"Call to System.find_executable/1 — probes for executables on the system",
     meta[:line] || 0, meta[:column]}
  end

  # :os.cmd/1
  defp match_pattern({{:., _, [:os, :cmd]}, meta, _args}) do
    {"Call to :os.cmd/1 — executes an OS-level command via Erlang",
     meta[:line] || 0, meta[:column]}
  end

  # Port.open/2
  defp match_pattern({{:., _, [{:__aliases__, _, [:Port]}, :open]}, meta, _args}) do
    {"Call to Port.open/2 — opens an OS process port",
     meta[:line] || 0, meta[:column]}
  end

  defp match_pattern(_), do: nil
end
