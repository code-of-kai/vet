defmodule VetCore.Checks.SystemExec do
  @moduledoc false
  use VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :system_exec
  @base_severity :critical

  @patterns [
    {[:System], :cmd},
    {[:System], :shell},
    {[:System], :find_executable},
    {[:os], :cmd},
    {[:Port], :open}
  ]

  @pattern_set MapSet.new(@patterns)

  @descriptions %{
    {[:System], :cmd} => "Call to System.cmd/2,3 — executes an external system command",
    {[:System], :shell} => "Call to System.shell — executes a shell command",
    {[:System], :find_executable} =>
      "Call to System.find_executable/1 — probes for executables on the system",
    {[:os], :cmd} => "Call to :os.cmd/1 — executes an OS-level command via Erlang",
    {[:Port], :open} => "Call to Port.open/2 — opens an OS process port"
  }

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
         true <- Walker.matches_pattern?(module, func, @pattern_set) do
      is_ct = FileHelper.compile_time?(state.context_stack)
      severity = if is_ct, do: :critical, else: @base_severity
      line = meta[:line] || 0

      description =
        Map.get(@descriptions, {module, func}, "Call to #{format_call(module, func)}")

      %Finding{
        dep_name: dep_name,
        file_path: state.file_path,
        line: line,
        column: meta[:column],
        check_id: :system_exec,
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

  defp format_call([mod], func), do: "#{mod}.#{func}"
  defp format_call(mods, func), do: "#{Enum.join(mods, ".")}.#{func}"
end
