defmodule VetCore.Checks.AtomExhaustion do
  @moduledoc false
  use VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :dos_atom_exhaustion
  @base_severity :warning

  @patterns [
    {[:String], :to_atom},
    {[:List], :to_atom},
    {[:erlang], :binary_to_atom},
    {[:erlang], :list_to_atom}
  ]

  @pattern_set MapSet.new(@patterns)

  @descriptions %{
    {[:String], :to_atom} => "Call to String.to_atom — DoS via atom table exhaustion",
    {[:List], :to_atom} => "Call to List.to_atom — DoS via atom table exhaustion",
    {[:erlang], :binary_to_atom} =>
      "Call to :erlang.binary_to_atom — DoS via atom table exhaustion",
    {[:erlang], :list_to_atom} =>
      "Call to :erlang.list_to_atom — DoS via atom table exhaustion"
  }

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, state) do
    dep_name
    |> FileHelper.parsed_files(project_path, state)
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
        check_id: :atom_exhaustion,
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
